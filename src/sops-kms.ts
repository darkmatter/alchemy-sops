/**
 * KMS-wrapped SOPS decryption for runtimes that hold AWS credentials but no
 * age key and no `sops` binary — Cloudflare Workers assuming an IAM role
 * through OIDC, Lambda, ECS tasks.
 *
 * SOPS encrypts every leaf with AES-256-GCM under one random data key and
 * stores that key wrapped once per master key under `sops.kms[]` (for KMS)
 * or `sops.age[]` (for age). This backend asks the caller to unwrap one of
 * the `sops.kms[]` entries — via `kms:Decrypt` with whatever credentials the
 * runtime has — and then does the same leaf decryption as the age backend,
 * in-process with WebCrypto.
 *
 * Not verified: the document-level `sops.mac`. Each leaf is still
 * authenticated by its GCM tag and its path (SOPS's additional data), so a
 * value cannot be altered or moved; the MAC would additionally detect a
 * removed leaf. Same trade-off as the `sops-age` backend.
 */
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import { parse as parseYaml } from "yaml";

import {
  requestLabel,
  revealSecretString,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";
import { encodeDecryptedValue, normalizeSopsExtract } from "./sops-age.js";

/** One `sops.kms[]` entry: the data key wrapped by one KMS key. */
export interface SopsKmsEntry {
  readonly arn: string;
  /** Base64 KMS ciphertext of the 32-byte data key. */
  readonly enc: string;
  readonly created_at?: string;
  readonly aws_profile?: string;
  readonly role?: string;
  readonly context?: Readonly<Record<string, string>>;
}

export interface SopsKmsOptions {
  /**
   * Unwrap a data key: typically `kms:Decrypt` of `entry.enc` against
   * `entry.arn` with the runtime's credentials. Tried for each candidate
   * entry in document order until one succeeds.
   */
  readonly unwrapDataKey: (entry: SopsKmsEntry) => Effect.Effect<Uint8Array, unknown>;
  /** Only try entries whose `arn` matches (a role usually can decrypt with one key). */
  readonly keyArn?: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const fromBase64 = (value: string): Uint8Array =>
  Uint8Array.from(atob(value), (c) => c.charCodeAt(0));

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

// https://github.com/getsops/sops/blob/main/aes/cipher.go
const ENC_VALUE = /^ENC\[AES256_GCM,data:(.*),iv:(.+),tag:(.+),type:(.+)\]$/;

type SopsType = "str" | "int" | "float" | "bool" | "bytes";

const parseTyped = (plaintext: Uint8Array, type: string): unknown => {
  const text = decoder.decode(plaintext);
  switch (type as SopsType) {
    case "str":
      return text;
    case "int":
      return Number.parseInt(text, 10);
    case "float":
      return Number.parseFloat(text);
    case "bool":
      // sops writes Go-style "True"/"False"
      return text.toLowerCase() === "true";
    case "bytes":
      return text;
    default:
      throw new Error(`unknown SOPS value type "${type}"`);
  }
};

/** SOPS additional data: the key path joined by `:` with a trailing `:`; array indices are skipped. */
const additionalData = (path: ReadonlyArray<string | number>): Uint8Array =>
  encoder.encode(`${path.filter((segment) => typeof segment === "string").join(":")}:`);

const decryptLeaf = async (
  key: CryptoKey,
  value: string,
  path: ReadonlyArray<string | number>,
): Promise<unknown> => {
  const match = ENC_VALUE.exec(value);
  if (!match) return value; // plaintext leaf (encrypted_regex / unencrypted_suffix)
  const [, data, iv, tag, type] = match as unknown as [string, string, string, string, string];
  const dataBytes = fromBase64(data);
  const tagBytes = fromBase64(tag);
  const sealed = new Uint8Array(dataBytes.length + tagBytes.length);
  sealed.set(dataBytes);
  sealed.set(tagBytes, dataBytes.length);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(fromBase64(iv)), additionalData: toArrayBuffer(additionalData(path)), tagLength: 128 },
    key,
    toArrayBuffer(sealed),
  );
  return parseTyped(new Uint8Array(plaintext), type);
};

const decryptTree = async (
  key: CryptoKey,
  node: unknown,
  path: ReadonlyArray<string | number>,
): Promise<unknown> => {
  if (typeof node === "string") return decryptLeaf(key, node, path);
  if (Array.isArray(node)) {
    return Promise.all(node.map((item, index) => decryptTree(key, item, [...path, index])));
  }
  if (node !== null && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = await decryptTree(key, v, [...path, k]);
    }
    return out;
  }
  return node;
};

const selectPath = (tree: unknown, extract: string): unknown =>
  normalizeSopsExtract(extract)
    .split(".")
    .reduce<unknown>(
      (node, segment) =>
        node !== null && typeof node === "object"
          ? (node as Record<string, unknown>)[segment]
          : undefined,
      tree,
    );

/**
 * Decrypt a parsed SOPS document (with its `sops` metadata) using an
 * already-unwrapped data key. Master-key agnostic: this is the half every
 * backend shares once it has the data key.
 */
export const decryptSopsTreeWithDataKey = (
  document: Record<string, unknown>,
  dataKey: Uint8Array,
): Effect.Effect<Record<string, unknown>, SopsDecryptError> =>
  Effect.tryPromise({
    try: async () => {
      if (dataKey.length !== 32) {
        throw new Error(`SOPS data key must be 32 bytes, got ${dataKey.length}`);
      }
      const key = await crypto.subtle.importKey("raw", toArrayBuffer(dataKey), { name: "AES-GCM" }, false, [
        "decrypt",
      ]);
      const { sops: _metadata, ...tree } = document;
      return (await decryptTree(key, tree, [])) as Record<string, unknown>;
    },
    catch: (cause) =>
      new SopsDecryptError({
        message: "Failed to decrypt SOPS values with the unwrapped data key",
        path: "<inline>",
        cause,
      }),
  });

const parseDocument = (request: SopsCommandRequest): Effect.Effect<Record<string, unknown>, SopsDecryptError> =>
  Effect.try({
    try: () => {
      if (request.content === undefined) {
        throw new Error("The kms backend requires inline `content`; read the file first");
      }
      const text = revealSecretString(request.content);
      const format = request.inputType ?? request.outputType ?? "json";
      const parsed: unknown =
        format === "json" ? JSON.parse(text) : format === "yaml" ? parseYaml(text) : undefined;
      if (parsed === undefined) {
        throw new Error(`The kms backend supports json and yaml documents, not ${format}`);
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("SOPS document root must be an object");
      }
      return parsed as Record<string, unknown>;
    },
    catch: (cause) =>
      new SopsDecryptError({
        message: cause instanceof Error ? cause.message : "Failed to parse SOPS document",
        path: requestLabel(request),
        cause,
      }),
  });

const kmsEntries = (document: Record<string, unknown>, keyArn: string | undefined): ReadonlyArray<SopsKmsEntry> => {
  const metadata = document.sops as { kms?: unknown } | undefined;
  const entries = Array.isArray(metadata?.kms) ? (metadata.kms as SopsKmsEntry[]) : [];
  return entries.filter(
    (entry) => typeof entry?.arn === "string" && typeof entry?.enc === "string" && (!keyArn || entry.arn === keyArn),
  );
};

/**
 * A `SopsDecrypt` whose master key is AWS KMS. Plug it in wherever a
 * `decrypt` is accepted (`SopsFile`, `alchemy-sops/Config`) or call it
 * directly at the edge.
 */
export const runSopsKms =
  (options: SopsKmsOptions): SopsDecrypt =>
  (request) =>
    Effect.gen(function* () {
      const label = requestLabel(request);
      const document = yield* parseDocument(request);
      const entries = kmsEntries(document, options.keyArn);
      if (entries.length === 0) {
        return yield* new SopsDecryptError({
          message: options.keyArn
            ? `No sops.kms entry for ${options.keyArn}; the file is not encrypted to that key`
            : "No sops.kms entries; the file is not encrypted to any KMS key",
          path: label,
        });
      }

      const failures: unknown[] = [];
      let dataKey: Uint8Array | undefined;
      for (const entry of entries) {
        const attempt = yield* Effect.exit(options.unwrapDataKey(entry));
        if (Exit.isSuccess(attempt)) {
          dataKey = attempt.value;
          break;
        }
        failures.push({ arn: entry.arn, cause: attempt.cause });
      }
      if (!dataKey) {
        return yield* new SopsDecryptError({
          message: `Could not unwrap the SOPS data key with any of ${entries.length} KMS key(s)`,
          path: label,
          cause: failures,
        });
      }

      const tree = yield* decryptSopsTreeWithDataKey(document, dataKey);
      const selected = request.extract ? selectPath(tree, request.extract) : tree;
      if (request.extract && selected === undefined) {
        return yield* new SopsDecryptError({
          message: `No value at ${request.extract}`,
          path: label,
        });
      }
      return yield* Effect.try({
        try: () => encodeDecryptedValue(selected, request.outputType ?? request.inputType),
        catch: (cause) =>
          cause instanceof SopsDecryptError
            ? cause
            : new SopsDecryptError({ message: "Failed to encode decrypted value", path: label, cause }),
      });
    });

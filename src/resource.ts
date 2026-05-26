import type { Resource as AlchemyResource } from "alchemy";
import { Resource } from "alchemy";
import * as Diff from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";

import {
  type GenerateSecretTypesOptions,
  type MaterializedSecretDocument,
  type SecretRecord,
  type SecretTree,
  type SopsDocumentFormat,
  generateSecretTypes,
  materializeSecretDocument,
} from "./document.js";
import {
  SopsDecryptError,
  SopsFileReadError,
  SopsInputError,
  SopsParseError,
  SopsSecretPathError,
  type SopsError,
} from "./errors.js";
import {
  type MaybeRedactedString,
  type SecretStringInput,
  resolveOptionalSecretStringInput,
  resolveSecretStringInput,
  resolveSecretStringInputs,
  resolveSecretStringRecord,
  revealString,
} from "./input.js";
import {
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
  type SopsDecryptMemoizeOptions,
  memoizeDecrypt,
  runSopsAge,
  runSopsCli,
} from "./sops.js";

const PROVIDER_VERSION = 1;

export interface SopsRetryOptions {
  readonly times?: number;
  readonly delay?: Duration.Input;
}

export type SopsGeneratedTypesOptions = GenerateSecretTypesOptions;
export type SopsGeneratedTypesInput = true | SopsGeneratedTypesOptions;

export interface SopsFileOptions<R = never> {
  readonly path?: SecretStringInput<R>;
  readonly content?: SecretStringInput<R>;
  readonly url?: SecretStringInput<R>;
  readonly cwd?: SecretStringInput<R>;
  readonly format?: SopsDocumentFormat | SecretStringInput<R>;
  readonly inputType?: SopsCliFormat | SecretStringInput<R>;
  readonly outputType?: SopsCliFormat | SecretStringInput<R>;
  readonly backend?: SopsBackend | SecretStringInput<R>;
  readonly sopsBinary?: SecretStringInput<R>;
  readonly sopsArgs?: readonly SecretStringInput<R>[];
  readonly extract?: SecretStringInput<R>;
  readonly env?: Record<string, SecretStringInput<R>>;
  readonly ageKey?: SecretStringInput<R>;
  readonly ageKeyFile?: SecretStringInput<R>;
  readonly secrets?: Record<string, string>;
  readonly cache?: boolean;
  readonly types?: SopsGeneratedTypesInput;
  readonly timeoutMs?: number;
  readonly retry?: SopsRetryOptions;
}

export interface SopsFileProps {
  readonly path?: MaybeRedactedString;
  readonly content?: MaybeRedactedString;
  readonly url?: MaybeRedactedString;
  readonly cwd?: MaybeRedactedString;
  readonly format: SopsDocumentFormat;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly backend: SopsBackend;
  readonly sopsBinary: MaybeRedactedString;
  readonly sopsArgs: readonly MaybeRedactedString[];
  readonly extract?: MaybeRedactedString;
  readonly env: Record<string, MaybeRedactedString>;
  readonly ageKey?: MaybeRedactedString;
  readonly ageKeyFile?: MaybeRedactedString;
  readonly secrets?: Record<string, string>;
  readonly cache: boolean;
  readonly types?: SopsGeneratedTypesOptions;
  readonly timeoutMs: number;
  readonly retry: Required<SopsRetryOptions>;
}

export interface SopsFileAttributes {
  readonly path: string;
  readonly format: Exclude<SopsDocumentFormat, "auto">;
  readonly sourceHash: string;
  readonly data: SecretTree;
  readonly flat: SecretRecord;
  readonly secrets: SecretRecord;
  readonly topLevelKeys: readonly string[];
  readonly types?: string;
  readonly version: number;
}

export type SopsFileResource = AlchemyResource<
  "Sops.File",
  SopsFileProps,
  SopsFileAttributes
>;

export interface SopsFileProviderOptions {
  readonly decrypt?: SopsDecrypt;
  readonly memoize?: boolean | SopsDecryptMemoizeOptions;
}

export const SopsFileResource = Resource<SopsFileResource>("Sops.File");

export const SopsFile = <R = never>(
  id: string,
  options: SopsFileOptions<R>,
): Effect.Effect<
  SopsFileResource,
  never,
  R | Provider.Provider<SopsFileResource>
> =>
  SopsFileResource(id, normalizeOptions(options));

export const SopsFileProvider = (options: SopsFileProviderOptions = {}) => {
  const decrypts = new Map<string, SopsDecrypt>();
  const decryptFor = (backend: SopsBackend, format: SopsDocumentFormat) => {
    const base = options.decrypt ?? defaultDecrypt(backend, format);
    if (!options.memoize) return base;

    const key = options.decrypt ? "custom" : `${backend}:${format}`;
    const existing = decrypts.get(key);
    if (existing) return existing;

    const memoized = memoizeDecrypt(
      base,
      options.memoize === true ? undefined : options.memoize,
    );
    decrypts.set(key, memoized);
    return memoized;
  };

  return Provider.succeed(SopsFileResource, {
    version: PROVIDER_VERSION,
    read: Effect.fn(function* ({ output }) {
      return output;
    }),
    diff: Effect.fn(function* ({ news, olds, output }) {
      if (!Diff.isResolved(news)) return undefined;
      if (!output) return undefined;
      if (!sameProps(olds, news)) return { action: "update" as const };
      if (!news.cache) return { action: "update" as const };

      const sourceHash = yield* hashSource(news);
      return output.sourceHash === sourceHash &&
        output.version === PROVIDER_VERSION
        ? { action: "noop" as const }
        : { action: "update" as const };
    }),
    reconcile: Effect.fn(function* ({ news, output, session }) {
      const source = yield* loadEncryptedSource(news);
      const sourceHash = yield* hashLoadedSource(news, source);
      if (
        news.cache &&
        output?.sourceHash === sourceHash &&
        output.version === PROVIDER_VERSION
      ) {
        return output;
      }

      yield* session.note(`Decrypting ${source.label}`);

      const outputType = news.outputType ?? defaultOutputType(news.format);
      const request: SopsCommandRequest = {
        binary: revealString(news.sopsBinary),
        args: news.sopsArgs.map(revealString),
        env: commandEnv(news),
        timeoutMs: news.timeoutMs,
        content: source.content,
        ...(source.path ? { path: source.path } : {}),
        ...(source.url ? { url: source.url } : {}),
        ...(news.cwd ? { cwd: revealString(news.cwd) } : {}),
        ...(news.inputType ? { inputType: news.inputType } : {}),
        ...(outputType ? { outputType } : {}),
        ...(news.extract ? { extract: revealString(news.extract) } : {}),
      };
      const plaintext = yield* decryptWithRetry(
        decryptFor(news.backend, news.format),
        request,
        news.retry,
      );

      const materialized = yield* parseDecryptedDocument(
        plaintext,
        news,
        source.label,
      );
      yield* session.note(
        `Decrypted ${source.label}: top-level keys ${formatTopLevelKeys(
          materialized.topLevelKeys,
        )}`,
      );

      const generatedTypes = news.types
        ? generateSecretTypes(materialized.data, news.types)
        : undefined;

      return {
        path: source.label,
        format: materialized.format,
        sourceHash,
        data: materialized.data,
        flat: materialized.flat,
        secrets: materialized.secrets,
        topLevelKeys: materialized.topLevelKeys,
        ...(generatedTypes ? { types: generatedTypes } : {}),
        version: PROVIDER_VERSION,
      };
    }),
    delete: Effect.fn(function* () {
      return undefined;
    }),
  });
};

export const providers = SopsFileProvider;

const normalizeOptions = <R>(
  options: SopsFileOptions<R>,
): Effect.Effect<SopsFileProps, never, R> =>
  Effect.gen(function* () {
    const path = yield* resolveOptionalSecretStringInput(options.path);
    const content = yield* resolveOptionalSecretStringInput(options.content);
    const url = yield* resolveOptionalSecretStringInput(options.url);
    validateSourceOptions({
      ...(path !== undefined ? { path } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(url !== undefined ? { url } : {}),
    });

    const cwd = yield* resolveOptionalSecretStringInput(options.cwd);
    const format = normalizeDocumentFormat(
      yield* resolveSecretStringInput(options.format ?? "auto"),
      "format",
    );
    const inputType = normalizeOptionalCliFormat(
      yield* resolveOptionalSecretStringInput(options.inputType),
      "inputType",
    );
    const outputType = normalizeOptionalCliFormat(
      yield* resolveOptionalSecretStringInput(options.outputType),
      "outputType",
    );
    const backend = normalizeBackend(
      yield* resolveSecretStringInput(options.backend ?? "auto"),
    );
    const extract = yield* resolveOptionalSecretStringInput(options.extract);
    const ageKey = yield* resolveOptionalSecretStringInput(options.ageKey);
    const ageKeyFile = yield* resolveOptionalSecretStringInput(
      options.ageKeyFile,
    );

    return {
      format,
      backend,
      sopsBinary: yield* resolveSecretStringInput(options.sopsBinary ?? "sops"),
      sopsArgs: yield* resolveSecretStringInputs(options.sopsArgs),
      env: yield* resolveSecretStringRecord(options.env),
      cache: options.cache ?? true,
      ...(options.types ? { types: normalizeGeneratedTypes(options.types) } : {}),
      timeoutMs: options.timeoutMs ?? 30_000,
      retry: {
        times: options.retry?.times ?? 2,
        delay: options.retry?.delay ?? "250 millis",
      },
      ...(path !== undefined ? { path } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(url !== undefined ? { url } : {}),
      ...(cwd ? { cwd } : {}),
      ...(inputType ? { inputType } : {}),
      ...(outputType ? { outputType } : {}),
      ...(extract ? { extract } : {}),
      ...(ageKey ? { ageKey } : {}),
      ...(ageKeyFile ? { ageKeyFile } : {}),
      ...(options.secrets ? { secrets: options.secrets } : {}),
    };
  }).pipe(Effect.orDie);

const normalizeDocumentFormat = (
  value: MaybeRedactedString,
  field: string,
): SopsDocumentFormat => {
  const raw = revealString(value);
  if (
    raw === "auto" ||
    raw === "json" ||
    raw === "yaml" ||
    raw === "dotenv" ||
    raw === "text" ||
    raw === "binary"
  ) {
    return raw;
  }
  throw new SopsInputError({
    message: `Invalid ${field}: ${raw}`,
    field,
  });
};

const normalizeBackend = (value: MaybeRedactedString): SopsBackend => {
  const raw = revealString(value);
  if (raw === "auto" || raw === "cli" || raw === "sops-age") return raw;

  throw new SopsInputError({
    message: `Invalid backend: ${raw}`,
    field: "backend",
  });
};

const validateSourceOptions = (source: {
  readonly path?: MaybeRedactedString;
  readonly content?: MaybeRedactedString;
  readonly url?: MaybeRedactedString;
}): void => {
  const provided = [source.path, source.content, source.url].filter(
    (value) => value !== undefined,
  );

  if (provided.length === 1) return;

  throw new SopsInputError({
    message:
      "Exactly one SOPS source must be provided: path, content, or url",
    field: "path",
  });
};

const normalizeOptionalCliFormat = (
  value: MaybeRedactedString | undefined,
  field: string,
): SopsCliFormat | undefined => {
  if (value === undefined) return undefined;
  const raw = revealString(value);
  if (raw === "json" || raw === "yaml" || raw === "dotenv" || raw === "binary") {
    return raw;
  }
  throw new SopsInputError({
    message: `Invalid ${field}: ${raw}`,
    field,
  });
};

const defaultOutputType = (
  format: SopsDocumentFormat,
): SopsCliFormat | undefined => {
  switch (format) {
    case "yaml":
      return "yaml";
    case "dotenv":
      return "dotenv";
    case "binary":
      return "binary";
    case "text":
      return undefined;
    case "auto":
    case "json":
      return "json";
  }
};

const decryptWithRetry = (
  decrypt: SopsDecrypt,
  request: SopsCommandRequest,
  retry: Required<SopsRetryOptions>,
) =>
  decrypt(request).pipe(
    Effect.retry({
      schedule: Schedule.spaced(retry.delay).pipe(
        Schedule.both(Schedule.recurs(retry.times)),
      ),
    }),
  );

const defaultDecrypt = (
  backend: SopsBackend,
  format: SopsDocumentFormat,
): SopsDecrypt => {
  switch (backend) {
    case "cli":
      return runSopsCli;
    case "sops-age":
      return runSopsAge;
    case "auto":
      return format === "binary" || format === "text"
        ? runSopsCli
        : runSopsAgeWithCliFallback;
  }
};

const runSopsAgeWithCliFallback: SopsDecrypt = (request) =>
  runSopsAge(request).pipe(
    Effect.catchIf(
      () => true,
      (nativeError) => {
        if (!request.path) return Effect.fail(nativeError);

        return runSopsCli(request).pipe(
          Effect.catchIf(
            () => true,
            (cliError) =>
              Effect.fail(
                new SopsDecryptError({
                  message: "Both sops-age and the sops CLI failed to decrypt",
                  path: request.path ?? "<inline>",
                  cause: { nativeError, cliError },
                }),
              ),
          ),
        );
      },
    ),
  );

const parseDecryptedDocument = (
  plaintext: string,
  props: SopsFileProps,
  sourceLabel: string,
): Effect.Effect<MaterializedSecretDocument, SopsParseError | SopsError> =>
  Effect.try({
    try: () =>
      materializeSecretDocument(plaintext, {
        format: props.format,
        path: sourceLabel,
        ...(props.secrets ? { secrets: props.secrets } : {}),
      }),
    catch: (cause) =>
      cause instanceof SopsParseError
        ? cause
        : cause instanceof SopsSecretPathError
        ? cause
        : new SopsParseError({
            message: "Failed to materialize decrypted SOPS content",
            format: props.format,
            cause,
          }),
  });

interface LoadedEncryptedSource {
  readonly label: string;
  readonly content: string;
  readonly bytes: Uint8Array;
  readonly path?: string;
  readonly url?: string;
}

const hashSource = (props: SopsFileProps) =>
  Effect.flatMap(loadEncryptedSource(props), (source) =>
    hashLoadedSource(props, source),
  );

const loadEncryptedSource = (
  props: SopsFileProps,
): Effect.Effect<LoadedEncryptedSource, SopsFileReadError> =>
  Effect.tryPromise({
    try: async () => {
      if (props.content !== undefined) {
        const content = revealString(props.content);
        return {
          label: "<inline>",
          content,
          bytes: new TextEncoder().encode(content),
        };
      }

      if (props.url !== undefined) {
        const url = revealString(props.url);
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status} while reading ${url}`);
        }
        const content = await response.text();
        return {
          label: url,
          url,
          content,
          bytes: new TextEncoder().encode(content),
        };
      }

      const path = await resolveResourcePath(props);
      const bytes = await readPathBytes(path);
      return {
        label: path,
        path,
        content: new TextDecoder().decode(bytes),
        bytes,
      };
    },
    catch: (cause) =>
      new SopsFileReadError({
        message: `Failed to read encrypted SOPS source: ${sourceLabel(props)}`,
        path: sourceLabel(props),
        cause,
      }),
  });

const hashLoadedSource = (
  props: SopsFileProps,
  source: LoadedEncryptedSource,
): Effect.Effect<string, SopsFileReadError> =>
  Effect.tryPromise({
    try: () =>
      sha256Hex([
        source.bytes,
        new TextEncoder().encode("\0"),
        new TextEncoder().encode(
          JSON.stringify({
            source: source.label,
            format: props.format,
            inputType: props.inputType,
            outputType: props.outputType,
            backend: props.backend,
            extract: props.extract ? revealString(props.extract) : undefined,
            sopsArgs: props.sopsArgs.map(revealString),
            secrets: props.secrets,
            providerVersion: PROVIDER_VERSION,
            types: props.types,
          }),
        ),
      ]),
    catch: (cause) =>
      new SopsFileReadError({
        message: `Failed to hash encrypted SOPS source: ${source.label}`,
        path: source.label,
        cause,
      }),
  });

const sourceLabel = (props: SopsFileProps): string => {
  if (props.path !== undefined) return revealString(props.path);
  if (props.url !== undefined) return revealString(props.url);
  return "<inline>";
};

const resolveResourcePath = async (props: SopsFileProps): Promise<string> => {
  if (props.path === undefined) {
    throw new Error("path source is missing");
  }

  const rawPath = revealString(props.path);
  const cwd = props.cwd ? revealString(props.cwd) : undefined;

  if (isAbsolutePath(rawPath)) return rawPath;

  if (typeof process !== "undefined" && process.cwd) {
    const { resolve } = await import("node:path");
    return resolve(cwd ?? process.cwd(), rawPath);
  }

  if (cwd) {
    return new URL(rawPath, cwd).toString();
  }

  return rawPath;
};

const isAbsolutePath = (path: string): boolean =>
  path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path);

const readPathBytes = async (path: string): Promise<Uint8Array> => {
  const runtime = globalThis as typeof globalThis & {
    Bun?: {
      file: (path: string) => { arrayBuffer: () => Promise<ArrayBuffer> };
    };
    Deno?: {
      readFile: (path: string) => Promise<Uint8Array>;
    };
  };

  if (runtime.Bun) {
    return new Uint8Array(await runtime.Bun.file(path).arrayBuffer());
  }

  if (runtime.Deno) {
    return runtime.Deno.readFile(path);
  }

  if (typeof process !== "undefined" && process.versions?.node) {
    const { readFile } = await import("node:fs/promises");
    return readFile(path);
  }

  throw new Error(`Unable to read local file source "${path}"`);
};

const sha256Hex = async (parts: readonly Uint8Array[]): Promise<string> => {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }

  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  const { createHash } = await import("node:crypto");
  const hash = createHash("sha256");
  hash.update(bytes);
  return hash.digest("hex");
};

const bytesToHex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const commandEnv = (
  props: SopsFileProps,
): Record<string, string | Redacted.Redacted<string>> => {
  const env: Record<string, string | Redacted.Redacted<string>> = {
    ...props.env,
  };

  if (props.ageKey) env.SOPS_AGE_KEY = props.ageKey;
  if (props.ageKeyFile) env.SOPS_AGE_KEY_FILE = props.ageKeyFile;

  return env;
};

const sameProps = (
  olds: SopsFileProps | undefined,
  news: SopsFileProps,
): boolean => JSON.stringify(olds ?? {}) === JSON.stringify(news);

const normalizeGeneratedTypes = (
  options: SopsGeneratedTypesInput,
): SopsGeneratedTypesOptions =>
  options === true ? {} : options;

const formatTopLevelKeys = (keys: readonly string[]): string =>
  keys.length === 0 ? "(none)" : keys.join(", ");

import * as Redacted from "effect/Redacted";
import { parse as parseYaml } from "yaml";

import { SopsParseError, SopsSecretPathError } from "./errors.js";

export type SopsDocumentFormat =
  | "auto"
  | "json"
  | "yaml"
  | "dotenv"
  | "text"
  | "binary";

export type ResolvedSopsDocumentFormat = Exclude<SopsDocumentFormat, "auto">;

export type SecretTree =
  | Redacted.Redacted<string>
  | { readonly [key: string]: SecretTree }
  | readonly SecretTree[];

export type SecretRecord = Record<string, Redacted.Redacted<string>>;

export interface MaterializeSecretDocumentOptions {
  readonly format?: SopsDocumentFormat;
  readonly path?: string;
  readonly secrets?: Record<string, string>;
}

export interface MaterializedSecretDocument {
  readonly format: ResolvedSopsDocumentFormat;
  readonly data: SecretTree;
  readonly flat: SecretRecord;
  readonly secrets: SecretRecord;
}

export const materializeSecretDocument = (
  plaintext: string,
  options: MaterializeSecretDocumentOptions = {},
): MaterializedSecretDocument => {
  const format = resolveDocumentFormat(options.format ?? "auto", options.path);
  const parsed = parsePlaintext(plaintext, format);
  const data = redactLeaves(parsed);
  const flat = flattenSecretTree(data);
  const secrets = selectSecrets(flat, options.secrets);

  return {
    format,
    data,
    flat,
    secrets,
  };
};

export const resolveDocumentFormat = (
  format: SopsDocumentFormat,
  filePath?: string,
): ResolvedSopsDocumentFormat => {
  if (format !== "auto") return format;

  const lower = filePath?.toLowerCase() ?? "";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  if (lower.endsWith(".env") || lower.endsWith(".dotenv")) return "dotenv";
  return "json";
};

const parsePlaintext = (
  plaintext: string,
  format: ResolvedSopsDocumentFormat,
): unknown => {
  try {
    switch (format) {
      case "json":
        return JSON.parse(plaintext) as unknown;
      case "yaml":
        return parseYaml(plaintext) as unknown;
      case "dotenv":
        return parseDotenv(plaintext);
      case "text":
        return plaintext;
      case "binary":
        return Buffer.from(plaintext, "binary").toString("base64");
    }
  } catch (cause) {
    throw new SopsParseError({
      message: `Failed to parse decrypted SOPS content as ${format}`,
      format,
      cause,
    });
  }
};

const parseDotenv = (plaintext: string): Record<string, string> => {
  const values: Record<string, string> = {};

  for (const rawLine of plaintext.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;

    const separator = line.indexOf("=");
    if (separator < 0) continue;

    const key = line.slice(0, separator).trim();
    const rawValue = line.slice(separator + 1).trim();
    values[key] = unquoteDotenvValue(rawValue);
  }

  return values;
};

const unquoteDotenvValue = (value: string): string => {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
};

const redactLeaves = (value: unknown): SecretTree => {
  if (Array.isArray(value)) {
    return value.map(redactLeaves);
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, child]) => [
        key,
        redactLeaves(child),
      ]),
    );
  }

  return Redacted.make(stringifyScalar(value));
};

const stringifyScalar = (value: unknown): string => {
  if (value === undefined) return "";
  if (value === null) return "null";
  if (typeof value === "string") return value;
  return String(value);
};

const flattenSecretTree = (
  tree: SecretTree,
  prefix = "",
): SecretRecord => {
  if (Redacted.isRedacted(tree)) {
    return prefix === "" ? { value: tree } : { [prefix]: tree };
  }

  if (Array.isArray(tree)) {
    return Object.assign(
      {},
      ...tree.map((value, index) =>
        flattenSecretTree(value, `${prefix}[${index}]`),
      ),
    );
  }

  return Object.assign(
    {},
    ...Object.entries(tree).map(([key, value]) =>
      flattenSecretTree(value, prefix === "" ? key : `${prefix}.${key}`),
    ),
  );
};

const selectSecrets = (
  flat: SecretRecord,
  selectors: Record<string, string> | undefined,
): SecretRecord => {
  if (!selectors) return flat;

  const selected: SecretRecord = {};
  for (const [name, path] of Object.entries(selectors)) {
    const value = flat[path];
    if (!value) {
      throw new SopsSecretPathError({
        message: `Secret path "${path}" was not found in decrypted SOPS content`,
        path,
      });
    }
    selected[name] = value;
  }
  return selected;
};

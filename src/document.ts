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

export interface MaterializeSecretValueOptions {
  readonly format: ResolvedSopsDocumentFormat;
  readonly secrets?: Record<string, string>;
}

export interface ParsedSecretDocument {
  readonly format: ResolvedSopsDocumentFormat;
  readonly value: unknown;
}

export interface GenerateSecretTypesOptions {
  readonly exportName?: string;
}

type MaterializedSecretDocumentBase = {
  readonly format: ResolvedSopsDocumentFormat;
  readonly data: SecretTree;
  readonly flat: SecretRecord;
  readonly secrets: SecretRecord;
  readonly topLevelKeys: readonly string[];
};

export type MaterializedSecretDocument<Value = never> =
  MaterializedSecretDocumentBase &
    ([Value] extends [never] ? {} : { readonly value: Value });

export const parseSecretDocument = (
  plaintext: string,
  options: MaterializeSecretDocumentOptions = {},
): ParsedSecretDocument => {
  const format = resolveDocumentFormat(options.format ?? "auto", options.path);
  return {
    format,
    value: parsePlaintext(plaintext, format),
  };
};

export const materializeSecretValue = <Value>(
  value: Value,
  options: MaterializeSecretValueOptions,
): MaterializedSecretDocument<Value> => {
  const data = redactLeaves(value);
  const flat = flattenSecretTree(data);
  const secrets = selectSecrets(flat, options.secrets);

  return {
    format: options.format,
    value,
    data,
    flat,
    secrets,
    topLevelKeys: topLevelSecretKeys(data),
  };
};

export const materializeSecretDocument = (
  plaintext: string,
  options: MaterializeSecretDocumentOptions = {},
): MaterializedSecretDocument => {
  const parsed = parseSecretDocument(plaintext, options);
  const { value: _value, ...materialized } = materializeSecretValue(
    parsed.value,
    {
      format: parsed.format,
      ...(options.secrets ? { secrets: options.secrets } : {}),
    },
  );
  return materialized;
};

export const generateSecretTypes = (
  tree: SecretTree,
  options: GenerateSecretTypesOptions = {},
): string => {
  const exportName = options.exportName ?? "SopsSecrets";
  const importLine = 'import type * as Redacted from "effect/Redacted";';

  if (!isObjectTree(tree)) {
    return `${importLine}

export type ${exportName} = ${renderSecretType(tree, 0)};
`;
  }

  return `${importLine}

export interface ${exportName} ${renderObjectType(tree, 0)}
`;
};

export const topLevelSecretKeys = (tree: SecretTree): readonly string[] => {
  if (Redacted.isRedacted(tree)) return ["value"];
  if (Array.isArray(tree)) return tree.map((_, index) => `[${index}]`);
  return Object.keys(tree);
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
        return binaryStringToBase64(plaintext);
    }
  } catch (cause) {
    throw new SopsParseError({
      message: `Failed to parse decrypted SOPS content as ${format}`,
      format,
      cause,
    });
  }
};

const binaryStringToBase64 = (plaintext: string): string => {
  if (typeof btoa === "function") return btoa(plaintext);

  const buffer = (
    globalThis as typeof globalThis & {
      Buffer?: {
        from: (
          input: string,
          encoding: "binary",
        ) => { toString: (encoding: "base64") => string };
      };
    }
  ).Buffer;

  if (buffer) return buffer.from(plaintext, "binary").toString("base64");

  throw new Error("No base64 encoder is available in this runtime");
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
  if (Redacted.isRedacted(value)) {
    return Redacted.make(stringifyScalar(Redacted.value(value)));
  }

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

const renderSecretType = (tree: SecretTree, indentLevel: number): string => {
  if (Redacted.isRedacted(tree)) return "Redacted.Redacted<string>";

  if (Array.isArray(tree)) {
    const itemType =
      tree.length === 0
        ? "Redacted.Redacted<string>"
        : renderArrayItemType(tree, indentLevel);
    return `readonly ${itemType}[]`;
  }

  return renderObjectType(
    tree as { readonly [key: string]: SecretTree },
    indentLevel,
  );
};

const renderArrayItemType = (
  values: readonly SecretTree[],
  indentLevel: number,
): string => {
  const rendered = values.map((value) => renderSecretType(value, indentLevel));
  const unique = [...new Set(rendered)];
  return unique.length === 1 ? unique[0]! : `(${unique.join(" | ")})`;
};

const renderObjectType = (
  tree: { readonly [key: string]: SecretTree },
  indentLevel: number,
): string => {
  const currentIndent = indent(indentLevel);
  const childIndent = indent(indentLevel + 1);
  const entries = Object.entries(tree);

  if (entries.length === 0) return "{}";

  const properties = entries
    .map(([key, value]) => {
      const rendered = renderSecretType(value, indentLevel + 1);
      return `${childIndent}readonly ${formatPropertyKey(key)}: ${rendered};`;
    })
    .join("\n");

  return `{\n${properties}\n${currentIndent}}`;
};

const isObjectTree = (
  tree: SecretTree,
): tree is { readonly [key: string]: SecretTree } =>
  !Redacted.isRedacted(tree) && !Array.isArray(tree);

const formatPropertyKey = (key: string): string =>
  /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key);

const indent = (level: number): string => "  ".repeat(level);

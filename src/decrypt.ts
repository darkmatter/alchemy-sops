import type * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

import { SopsDecryptError } from "./errors.js";

export type SopsCliFormat = "json" | "yaml" | "dotenv" | "binary";
export type SopsBackend = "auto" | "cli" | "sops-age";

export interface SopsCommandRequest {
  readonly path?: string;
  readonly content?: string | Redacted.Redacted<string>;
  readonly url?: string | Redacted.Redacted<string>;
  readonly cwd?: string;
  readonly binary: string;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly extract?: string;
  readonly args?: readonly string[];
  readonly env?: Record<string, string | Redacted.Redacted<string>>;
  readonly timeoutMs?: number;
}

export type SopsDecrypt = (
  request: SopsCommandRequest,
) => Effect.Effect<string, SopsDecryptError>;

export const buildSopsArgs = (request: SopsCommandRequest): string[] => {
  const path = requirePath(request);
  const args = ["--decrypt"];

  if (request.inputType) {
    args.push("--input-type", request.inputType);
  }
  if (request.outputType) {
    args.push("--output-type", request.outputType);
  }
  if (request.extract) {
    args.push("--extract", request.extract);
  }
  args.push(...(request.args ?? []));
  args.push(path);

  return args;
};

export const requirePath = (request: SopsCommandRequest): string => {
  if (request.path) return request.path;

  throw new SopsDecryptError({
    message: "The sops CLI backend requires a local path source",
    path: requestLabel(request),
  });
};

export const requestLabel = (request: SopsCommandRequest): string => {
  if (request.path) return request.path;
  if (request.url) return revealSecretString(request.url);
  return "<inline>";
};

export const revealSecretString = (
  value: string | Redacted.Redacted<string>,
): string => (Redacted.isRedacted(value) ? Redacted.value(value) : value);

export const revealEnv = (
  env: Record<string, string | Redacted.Redacted<string>> | undefined,
) =>
  Object.fromEntries(
    Object.entries(env ?? {}).map(([key, value]) => [
      key,
      revealSecretString(value),
    ]),
  );

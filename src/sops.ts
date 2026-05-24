import { spawn } from "node:child_process";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

import { SopsDecryptError } from "./errors.js";

export type SopsCliFormat = "json" | "yaml" | "dotenv" | "binary";

export interface SopsCommandRequest {
  readonly path: string;
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

export const runSopsCli: SopsDecrypt = (request) =>
  Effect.tryPromise({
    try: () => runSopsCliPromise(request),
    catch: (cause) =>
      cause instanceof SopsDecryptError
        ? cause
        : new SopsDecryptError({
            message: "Failed to run sops",
            path: request.path,
            cause,
          }),
  });

const runSopsCliPromise = (request: SopsCommandRequest): Promise<string> =>
  new Promise((resolve, reject) => {
    const args = buildSopsArgs(request);
    const env = {
      ...process.env,
      ...revealEnv(request.env),
    };

    const child = spawn(request.binary, args, {
      cwd: request.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timeout =
      request.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill("SIGTERM");
          }, request.timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (cause) => {
      if (timeout) clearTimeout(timeout);
      reject(
        new SopsDecryptError({
          message: `Failed to start sops binary "${request.binary}"`,
          path: request.path,
          cause,
        }),
      );
    });
    child.on("close", (exitCode) => {
      if (timeout) clearTimeout(timeout);
      if (timedOut) {
        const error = {
          message: `sops timed out after ${request.timeoutMs}ms`,
          path: request.path,
          ...(exitCode === null ? {} : { exitCode }),
          ...(stderr.trim() ? { stderr: stderr.trim() } : {}),
        };
        reject(new SopsDecryptError(error));
        return;
      }
      if (exitCode === 0) {
        resolve(stdout);
        return;
      }
      const error = {
        message: `sops exited with code ${exitCode}`,
        path: request.path,
        ...(exitCode === null ? {} : { exitCode }),
        ...(stderr.trim() ? { stderr: stderr.trim() } : {}),
      };
      reject(new SopsDecryptError(error));
    });
  });

export const buildSopsArgs = (request: SopsCommandRequest): string[] => {
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
  args.push(request.path);

  return args;
};

const revealEnv = (
  env: Record<string, string | Redacted.Redacted<string>> | undefined,
) =>
  Object.fromEntries(
    Object.entries(env ?? {}).map(([key, value]) => [
      key,
      Redacted.isRedacted(value) ? Redacted.value(value) : value,
    ]),
  );

import type { Resource as AlchemyResource } from "alchemy";
import { Resource } from "alchemy";
import * as Diff from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";

import {
  type MaterializedSecretDocument,
  type SecretRecord,
  type SecretTree,
  type SopsDocumentFormat,
  materializeSecretDocument,
} from "./document.js";
import {
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
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
  runSopsCli,
} from "./sops.js";

const PROVIDER_VERSION = 1;

export interface SopsRetryOptions {
  readonly times?: number;
  readonly delay?: Duration.Input;
}

export interface SopsFileOptions<R = never> {
  readonly path: SecretStringInput<R>;
  readonly cwd?: SecretStringInput<R>;
  readonly format?: SopsDocumentFormat | SecretStringInput<R>;
  readonly inputType?: SopsCliFormat | SecretStringInput<R>;
  readonly outputType?: SopsCliFormat | SecretStringInput<R>;
  readonly sopsBinary?: SecretStringInput<R>;
  readonly sopsArgs?: readonly SecretStringInput<R>[];
  readonly extract?: SecretStringInput<R>;
  readonly env?: Record<string, SecretStringInput<R>>;
  readonly ageKey?: SecretStringInput<R>;
  readonly ageKeyFile?: SecretStringInput<R>;
  readonly secrets?: Record<string, string>;
  readonly cache?: boolean;
  readonly timeoutMs?: number;
  readonly retry?: SopsRetryOptions;
}

export interface SopsFileProps {
  readonly path: MaybeRedactedString;
  readonly cwd?: MaybeRedactedString;
  readonly format: SopsDocumentFormat;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly sopsBinary: MaybeRedactedString;
  readonly sopsArgs: readonly MaybeRedactedString[];
  readonly extract?: MaybeRedactedString;
  readonly env: Record<string, MaybeRedactedString>;
  readonly ageKey?: MaybeRedactedString;
  readonly ageKeyFile?: MaybeRedactedString;
  readonly secrets?: Record<string, string>;
  readonly cache: boolean;
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
  readonly version: number;
}

export type SopsFileResource = AlchemyResource<
  "Sops.File",
  SopsFileProps,
  SopsFileAttributes
>;

export interface SopsFileProviderOptions {
  readonly decrypt?: SopsDecrypt;
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

export const SopsFileProvider = (
  options: SopsFileProviderOptions = {},
) =>
  Provider.succeed(SopsFileResource, {
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
      const sourceHash = yield* hashSource(news);
      if (
        news.cache &&
        output?.sourceHash === sourceHash &&
        output.version === PROVIDER_VERSION
      ) {
        return output;
      }

      yield* session.note(`Decrypting ${revealString(news.path)}`);

      const outputType = news.outputType ?? defaultOutputType(news.format);
      const request: SopsCommandRequest = {
        path: revealString(news.path),
        binary: revealString(news.sopsBinary),
        args: news.sopsArgs.map(revealString),
        env: commandEnv(news),
        timeoutMs: news.timeoutMs,
        ...(news.cwd ? { cwd: revealString(news.cwd) } : {}),
        ...(news.inputType ? { inputType: news.inputType } : {}),
        ...(outputType ? { outputType } : {}),
        ...(news.extract ? { extract: revealString(news.extract) } : {}),
      };
      const plaintext = yield* decryptWithRetry(
        options.decrypt ?? runSopsCli,
        request,
        news.retry,
      );

      const materialized = yield* parseDecryptedDocument(plaintext, news);

      return {
        path: toAbsolutePath(news),
        format: materialized.format,
        sourceHash,
        data: materialized.data,
        flat: materialized.flat,
        secrets: materialized.secrets,
        version: PROVIDER_VERSION,
      };
    }),
    delete: Effect.fn(function* () {
      return undefined;
    }),
  });

export const providers = SopsFileProvider;

const normalizeOptions = <R>(
  options: SopsFileOptions<R>,
): Effect.Effect<SopsFileProps, never, R> =>
  Effect.gen(function* () {
    const path = yield* resolveSecretStringInput(options.path);
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
    const extract = yield* resolveOptionalSecretStringInput(options.extract);
    const ageKey = yield* resolveOptionalSecretStringInput(options.ageKey);
    const ageKeyFile = yield* resolveOptionalSecretStringInput(
      options.ageKeyFile,
    );

    return {
      path,
      format,
      sopsBinary: yield* resolveSecretStringInput(options.sopsBinary ?? "sops"),
      sopsArgs: yield* resolveSecretStringInputs(options.sopsArgs),
      env: yield* resolveSecretStringRecord(options.env),
      cache: options.cache ?? true,
      timeoutMs: options.timeoutMs ?? 30_000,
      retry: {
        times: options.retry?.times ?? 2,
        delay: options.retry?.delay ?? "250 millis",
      },
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

const parseDecryptedDocument = (
  plaintext: string,
  props: SopsFileProps,
): Effect.Effect<MaterializedSecretDocument, SopsParseError | SopsError> =>
  Effect.try({
    try: () =>
      materializeSecretDocument(plaintext, {
        format: props.format,
        path: revealString(props.path),
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

const hashSource = (props: SopsFileProps) =>
  Effect.tryPromise({
    try: async () => {
      const bytes = await readFile(toAbsolutePath(props));
      const hash = createHash("sha256");
      hash.update(bytes);
      hash.update("\0");
      hash.update(
        JSON.stringify({
          format: props.format,
          inputType: props.inputType,
          outputType: props.outputType,
          extract: props.extract ? revealString(props.extract) : undefined,
          sopsArgs: props.sopsArgs.map(revealString),
          secrets: props.secrets,
          providerVersion: PROVIDER_VERSION,
        }),
      );
      return hash.digest("hex");
    },
    catch: (cause) =>
      new SopsFileReadError({
        message: `Failed to read encrypted SOPS file: ${revealString(props.path)}`,
        path: revealString(props.path),
        cause,
      }),
  });

const toAbsolutePath = (props: SopsFileProps): string =>
  resolvePath(
    props.cwd ? revealString(props.cwd) : process.cwd(),
    revealString(props.path),
  );

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

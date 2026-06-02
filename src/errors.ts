import * as Data from "effect/Data";

export class SopsInputError extends Data.TaggedError("SopsInputError")<{
  readonly message: string;
  readonly field?: string;
  readonly cause?: unknown;
}> {}

export class SopsFileReadError extends Data.TaggedError("SopsFileReadError")<{
  readonly message: string;
  readonly path: string;
  readonly cause?: unknown;
}> {}

export class SopsDecryptError extends Data.TaggedError("SopsDecryptError")<{
  readonly message: string;
  readonly path: string;
  readonly exitCode?: number;
  readonly stderr?: string;
  readonly cause?: unknown;
}> {}

export class SopsParseError extends Data.TaggedError("SopsParseError")<{
  readonly message: string;
  readonly format: string;
  readonly cause?: unknown;
}> {}

export class SopsSecretPathError extends Data.TaggedError(
  "SopsSecretPathError",
)<{
  readonly message: string;
  readonly path: string;
}> {}

export class SopsSchemaError extends Data.TaggedError("SopsSchemaError")<{
  readonly message: string;
  readonly path: string;
  readonly cause?: unknown;
}> {}

export type SopsError =
  | SopsInputError
  | SopsFileReadError
  | SopsDecryptError
  | SopsParseError
  | SopsSecretPathError
  | SopsSchemaError;

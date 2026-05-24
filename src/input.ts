import type * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

export type MaybeRedactedString = string | Redacted.Redacted<string>;

export type SecretStringInput<R = never> =
  | string
  | Redacted.Redacted<string>
  | Effect.Effect<string | Redacted.Redacted<string>, any, R>
  | Config.Config<string | Redacted.Redacted<string>>;

export const resolveSecretStringInput = <R = never>(
  input: SecretStringInput<R>,
): Effect.Effect<string | Redacted.Redacted<string>, any, R> => {
  if (Effect.isEffect(input)) {
    return input as Effect.Effect<string | Redacted.Redacted<string>, any, R>;
  }
  return Effect.succeed(input);
};

export const revealString = (value: MaybeRedactedString): string =>
  Redacted.isRedacted(value) ? Redacted.value(value) : value;

export const resolveOptionalSecretStringInput = <R = never>(
  input: SecretStringInput<R> | undefined,
): Effect.Effect<string | Redacted.Redacted<string> | undefined, any, R> =>
  input === undefined
    ? Effect.succeed(undefined)
    : resolveSecretStringInput(input);

export const resolveSecretStringInputs = <R = never>(
  inputs: readonly SecretStringInput<R>[] | undefined,
): Effect.Effect<readonly (string | Redacted.Redacted<string>)[], any, R> =>
  Effect.all((inputs ?? []).map((input) => resolveSecretStringInput(input)), {
    concurrency: "unbounded",
  });

export const resolveSecretStringRecord = <R = never>(
  input: Record<string, SecretStringInput<R>> | undefined,
): Effect.Effect<Record<string, string | Redacted.Redacted<string>>, any, R> =>
  Effect.gen(function* () {
    const entries = Object.entries(input ?? {});
    const resolved = yield* Effect.all(
      entries.map(([key, value]) =>
        resolveSecretStringInput(value).pipe(
          Effect.map((resolvedValue) => [key, resolvedValue] as const),
        ),
      ),
      { concurrency: "unbounded" },
    );
    return Object.fromEntries(resolved);
  });

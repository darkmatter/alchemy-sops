import { expect, test } from "bun:test";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as SchemaIssue from "effect/SchemaIssue";

import type { SopsDecryptError } from "../src/errors.ts";
import * as SopsSchema from "../src/Schema.ts";
import nativeEncrypted from "./fixtures/native.enc.json" with { type: "json" };

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;
type Expect<T extends true> = T;

const AGE_SECRET_KEY = "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
const DECRYPT_OPTIONS = {
  ageKey: Redacted.make(AGE_SECRET_KEY),
} as const;

const NativeSchema = Schema.Struct({
  api: Schema.Struct({
    token: Schema.RedactedFromValue(Schema.String, { label: "api.token" }),
    enabled: Schema.Boolean,
  }),
  nested: Schema.Struct({
    count: Schema.Number,
  }),
});

const RequiredKeySchema = Schema.Struct({
  required: Schema.String,
});

const OptionalEncodedFieldSchema = Schema.Struct({
  required: Schema.String,
  optional: Schema.optionalKey(Schema.String),
});

const checkEncryptedDocumentTypes = () => {
  SopsSchema.decodeEffect(RequiredKeySchema)({
    required: "ciphertext",
    sops: {},
  });

  // @ts-expect-error `required` must be present in the encoded document.
  SopsSchema.decodeEffect(RequiredKeySchema)({ sops: {} });

  SopsSchema.decodeEffect(OptionalEncodedFieldSchema)({
    required: "ciphertext",
    sops: {},
  });
};
void checkEncryptedDocumentTypes;

interface TestDecodingService {
  readonly TestDecodingService: unique symbol;
}

type ServiceSchema = Schema.Struct<{
  readonly value: Schema.Codec<string, string, TestDecodingService>;
}>;
type ServiceDecoder = ReturnType<
  typeof SopsSchema.decodeEffect<ServiceSchema>
>;
type ServiceEffect = ReturnType<ServiceDecoder>;
type _PreservesEffectChannels = Expect<
  Equal<
    ServiceEffect,
    Effect.Effect<
      ServiceSchema["Type"],
      SopsDecryptError | Schema.SchemaError,
      TestDecodingService
    >
  >
>;

type DecodeFailure = SopsDecryptError | Schema.SchemaError;
type SafeOutcome<A> =
  | { readonly _tag: "Success"; readonly value: A }
  | {
      readonly _tag: "Failure";
      readonly errorTag: DecodeFailure["_tag"];
    };

const safeOutcome = <A>(
  effect: Effect.Effect<A, DecodeFailure>,
): Promise<SafeOutcome<A>> =>
  Effect.runPromise(
    effect.pipe(
      Effect.match({
        onFailure: (error) =>
          ({ _tag: "Failure", errorTag: error._tag }) as const,
        onSuccess: (value) => ({ _tag: "Success", value }) as const,
      }),
    ),
  );

const requireSuccess = <A>(outcome: SafeOutcome<A>): A => {
  if (outcome._tag === "Failure") {
    throw new Error(`Expected decode success, received ${outcome.errorTag}`);
  }
  return outcome.value;
};

const requireFailureTag = <A>(
  outcome: SafeOutcome<A>,
): DecodeFailure["_tag"] => {
  if (outcome._tag === "Success") {
    throw new Error("Expected decode failure");
  }
  return outcome.errorTag;
};

const asEncryptedFor = <S extends Schema.Struct<Schema.Struct.Fields>>(
  document: object,
): SopsSchema.EncryptedFor<S> =>
  document as SopsSchema.EncryptedFor<S>;

const countMissingKeys = (issue: SchemaIssue.Issue): number => {
  switch (issue._tag) {
    case "MissingKey":
      return 1;
    case "Encoding":
    case "Filter":
    case "Pointer":
      return countMissingKeys(issue.issue);
    case "AnyOf":
    case "Composite":
      return issue.issues.reduce(
        (total, child) => total + countMissingKeys(child),
        0,
      );
    default:
      return 0;
  }
};

test("decrypts imported JSON and decodes a redacted schema value", async () => {
  const decoded = requireSuccess(
    await safeOutcome(
      SopsSchema.decodeEffect(NativeSchema)(
        nativeEncrypted,
        DECRYPT_OPTIONS,
      ),
    ),
  );

  expect(Redacted.isRedacted(decoded.api.token)).toBe(true);
  expect(decoded.api.token.label).toBe("api.token");
  expect(decoded.api.enabled).toBe(true);
  expect(decoded.nested.count).toBe(3);
});

test("returns SchemaError when decrypted content lacks a required field", async () => {
  const schema = Schema.Struct({
    ...NativeSchema.fields,
    additionalRequired: Schema.String,
  });
  const outcome = await safeOutcome(
    SopsSchema.decodeEffect(schema)(
      asEncryptedFor<typeof schema>(nativeEncrypted),
      DECRYPT_OPTIONS,
    ),
  );

  expect(requireFailureTag(outcome)).toBe("SchemaError");
});

test("errors: all captures multiple missing fields", async () => {
  const schema = Schema.Struct({
    firstMissing: Schema.String,
    secondMissing: Schema.Number,
  });
  const summary = await Effect.runPromise(
    SopsSchema.decodeEffect(schema, { errors: "all" })(
      asEncryptedFor<typeof schema>(nativeEncrypted),
      DECRYPT_OPTIONS,
    ).pipe(
      Effect.match({
        onFailure: (error) => ({
          errorTag: error._tag,
          missingKeyCount: Schema.isSchemaError(error)
            ? countMissingKeys(error.issue)
            : 0,
        }),
        onSuccess: () => ({
          errorTag: "Success" as const,
          missingKeyCount: 0,
        }),
      }),
    ),
  );

  expect(summary.errorTag).toBe("SchemaError");
  expect(summary.missingKeyCount).toBe(2);
});

test("onExcessProperty rejects extras while default parsing decodes a subset", async () => {
  const subsetSchema = Schema.Struct({
    api: Schema.Struct({
      enabled: Schema.Boolean,
    }),
  });

  const decoded = requireSuccess(
    await safeOutcome(
      SopsSchema.decodeEffect(subsetSchema)(
        nativeEncrypted,
        DECRYPT_OPTIONS,
      ),
    ),
  );
  expect(decoded.api.enabled).toBe(true);
  expect(Object.keys(decoded)).toEqual(["api"]);
  expect(Object.keys(decoded.api)).toEqual(["enabled"]);

  const strictOutcome = await safeOutcome(
    SopsSchema.decodeEffect(subsetSchema, {
      onExcessProperty: "error",
    })(nativeEncrypted, DECRYPT_OPTIONS),
  );
  expect(requireFailureTag(strictOutcome)).toBe("SchemaError");
});

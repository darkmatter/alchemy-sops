/**
 * Type-level tests for SopsFile's JSON-import typing.
 *
 * Uses `expectTypeOf` from `expect-type` — the same type-testing utility Vitest
 * re-exports. These assertions are compile-time only and are enforced by
 * `bun run check` (tsc --noEmit); a type mismatch becomes a build error. The
 * `.test-d.ts` suffix keeps the Bun test runner from executing this file.
 */
import type * as Output from "alchemy/Output";
import type * as Effect from "effect/Effect";
import type * as Redacted from "effect/Redacted";
import { expectTypeOf } from "expect-type";

import { SopsFile, type SopsRedactedDocument } from "../src/index.ts";

// How TypeScript types an imported encrypted SOPS JSON document: the plaintext
// key structure is preserved, encrypted leaves are `string`, plus the top-level
// `sops` metadata block.
interface EncryptedDocument {
  api: { token: string; enabled: string };
  nested: { count: string };
  sops: { version: string; mac: string };
}

// The decrypted, redacted shape we expect: `sops` removed, every scalar leaf
// wrapped in `Redacted`, structure preserved.
interface ExpectedData {
  readonly api: {
    readonly token: Redacted.Redacted<string>;
    readonly enabled: Redacted.Redacted<string>;
  };
  readonly nested: {
    readonly count: Redacted.Redacted<string>;
  };
}

// The exported transform maps an imported document to the redacted shape.
expectTypeOf<SopsRedactedDocument<EncryptedDocument>>().toEqualTypeOf<ExpectedData>();

// The top-level `sops` metadata key is stripped from the typed output.
expectTypeOf<keyof SopsRedactedDocument<EncryptedDocument>>().toEqualTypeOf<
  "api" | "nested"
>();

// The inferred type is persisted through `SopsFile`: `secrets.data` carries the
// redacted document shape, with no schema and no secrets keys declared.
declare const encrypted: EncryptedDocument;
const secrets = SopsFile("Secrets", { json: encrypted });
type Secrets = Effect.Success<typeof secrets>;
type SecretsData = Secrets["data"] extends Output.Output<infer Data> ? Data : never;
expectTypeOf<SecretsData>().toEqualTypeOf<ExpectedData>();

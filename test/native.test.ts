import { expect, test } from "bun:test";
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { SopsFile, SopsFileProvider, runSopsAge } from "../src/index.ts";
import nativeEncrypted from "./fixtures/native.enc.json" with { type: "json" };

type IsAny<T> = 0 extends 1 & T ? true : false;
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;
type Expect<T extends true> = T;

const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";

const fixturePath = join(import.meta.dir, "fixtures/native.enc.json");

test("runSopsAge decrypts inline SOPS JSON without the sops binary", async () => {
  const content = await readFile(fixturePath, "utf8");
  const plaintext = await Effect.runPromise(
    runSopsAge({
      content,
      binary: "sops",
      inputType: "json",
      outputType: "json",
      env: {
        SOPS_AGE_KEY: Redacted.make(AGE_SECRET_KEY),
      },
    }),
  );

  expect(JSON.parse(plaintext)).toEqual({
    api: {
      token: "native-token",
      enabled: true,
    },
    nested: {
      count: 3,
    },
  });
});

const { test: providerTest } = Test.make({
  providers: SopsFileProvider(),
});

providerTest.provider(
  "decrypts inline content through the native backend",
  (stack) =>
    Effect.gen(function* () {
      const content = yield* Effect.promise(() => readFile(fixturePath, "utf8"));

      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          const file = yield* SopsFile("NativeInlineSecrets", {
            content,
            format: "json",
            backend: "sops-age",
            ageKey: Redacted.make(AGE_SECRET_KEY),
            secrets: {
              API_TOKEN: "api.token",
            },
          });

          return {
            apiToken: Output.map(
              file.secrets,
              (secrets) => secrets.API_TOKEN!,
            ),
            enabled: Output.map(file.flat, (secrets) => secrets["api.enabled"]!),
            count: Output.map(file.flat, (secrets) => secrets["nested.count"]!),
          };
        }),
      );

      yield* stack.destroy();

      expect(Redacted.value(deployed.apiToken)).toBe("native-token");
      expect(Redacted.value(deployed.enabled)).toBe("true");
      expect(Redacted.value(deployed.count)).toBe("3");
    }),
);

providerTest.provider(
  "types and decrypts an imported JSON document without a schema or keys",
  (stack) =>
    Effect.gen(function* () {
      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          // The encrypted document is imported directly; TypeScript infers its
          // shape and `SopsFile` propagates it to a redacted `data` output. No
          // `schema` and no `secrets` selectors are declared anywhere.
          const file = yield* SopsFile("ImportedJsonSecrets", {
            json: nativeEncrypted,
            backend: "sops-age",
            ageKey: Redacted.make(AGE_SECRET_KEY),
          });

          type DataType =
            typeof file.data extends Output.Output<infer Data> ? Data : never;
          // The inferred type is concrete, not `any`.
          type _DataIsNotAny = Expect<Equal<IsAny<DataType>, false>>;
          // Scalar leaves are redacted, mirroring the runtime `data` output.
          type _ApiTokenRedacted = Expect<
            Equal<DataType["api"]["token"], Redacted.Redacted<string>>
          >;
          type _ApiEnabledRedacted = Expect<
            Equal<DataType["api"]["enabled"], Redacted.Redacted<string>>
          >;
          type _NestedCountRedacted = Expect<
            Equal<DataType["nested"]["count"], Redacted.Redacted<string>>
          >;
          // The top-level SOPS metadata key is stripped from the typed output.
          type _SopsMetadataStripped = Expect<
            Equal<"sops" extends keyof DataType ? true : false, false>
          >;

          return {
            token: Output.map(file.data, (data) => data.api.token),
            enabled: Output.map(file.data, (data) => data.api.enabled),
            count: Output.map(file.data, (data) => data.nested.count),
            topLevelKeys: file.topLevelKeys,
          };
        }),
      );

      yield* stack.destroy();

      expect(Redacted.value(deployed.token)).toBe("native-token");
      expect(Redacted.value(deployed.enabled)).toBe("true");
      expect(Redacted.value(deployed.count)).toBe("3");
      expect(deployed.topLevelKeys).toEqual(["api", "nested"]);
    }),
);

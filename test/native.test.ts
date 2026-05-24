import { expect, test } from "bun:test";
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { SopsFile, SopsFileProvider, runSopsAge } from "../src/index.ts";

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

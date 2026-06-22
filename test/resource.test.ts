import { expect } from "bun:test";
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  SopsFile,
  SopsFileProvider,
  type SopsSchemaError,
  type SopsCommandRequest,
} from "../src/index.ts";

type IsAny<T> = 0 extends 1 & T ? true : false;
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;
type Expect<T extends true> = T;

const decryptCalls = new Map<string, number>();
const plaintextByPath = new Map<string, () => string>();

const { test } = Test.make({
  providers: SopsFileProvider({
    decrypt: (request: SopsCommandRequest) =>
      Effect.sync(() => {
        if (!request.path) {
          throw new Error("Expected a path-backed decrypt request");
        }

        decryptCalls.set(request.path, (decryptCalls.get(request.path) ?? 0) + 1);

        const plaintext = plaintextByPath.get(request.path);
        if (!plaintext) {
          throw new Error(`No test plaintext registered for ${request.path}`);
        }

        return plaintext();
      }),
  }),
});

const { test: memoizedTest } = Test.make({
  providers: SopsFileProvider({
    memoize: true,
    decrypt: (request: SopsCommandRequest) =>
      Effect.sync(() => {
        if (!request.path) {
          throw new Error("Expected a path-backed decrypt request");
        }

        decryptCalls.set(request.path, (decryptCalls.get(request.path) ?? 0) + 1);

        const plaintext = plaintextByPath.get(request.path);
        if (!plaintext) {
          throw new Error(`No test plaintext registered for ${request.path}`);
        }

        return plaintext();
      }),
  }),
});

test.provider(
  "create, noop, destroy a SOPS file resource",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "app.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () => '{"api":{"token":"first"}}');

      const create = Effect.gen(function* () {
        const file = yield* SopsFile("AppSecrets", {
          path: encryptedPath,
          format: "json",
          secrets: {
            API_TOKEN: "api.token",
          },
        });

        return {
          sourceHash: file.sourceHash,
          apiToken: Output.map(file.secrets, (secrets) => secrets.API_TOKEN!),
        };
      });

      const created = yield* stack.deploy(create);
      const unchanged = yield* stack.deploy(create);
      yield* stack.destroy();

      expect(decryptCalls.get(encryptedPath)).toBe(1);
      expect(unchanged.sourceHash).toBe(created.sourceHash);
      expect(Redacted.value(created.apiToken)).toBe("first");
      expect(Redacted.value(unchanged.apiToken)).toBe("first");
    }),
);

test.provider(
  "create, update, destroy when encrypted file content changes",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "rotating.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () => {
        const calls = decryptCalls.get(encryptedPath) ?? 0;
        return JSON.stringify({ token: `value-${calls}` });
      });

      const resource = Effect.gen(function* () {
        const file = yield* SopsFile("RotatingSecrets", {
          path: encryptedPath,
          format: "json",
        });

        return {
          token: Output.map(file.flat, (secrets) => secrets.token!),
        };
      });

      const created = yield* stack.deploy(resource);
      yield* Effect.promise(() => writeFile(encryptedPath, "ciphertext-v2"));
      const updated = yield* stack.deploy(resource);
      yield* stack.destroy();

      expect(decryptCalls.get(encryptedPath)).toBe(2);
      expect(Redacted.value(created.token)).toBe("value-1");
      expect(Redacted.value(updated.token)).toBe("value-2");
    }),
);

test.provider(
  "returns top-level keys and generated types",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "typed.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () =>
        JSON.stringify({
          api: { token: "first" },
          enabled: true,
        }),
      );

      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          const file = yield* SopsFile("TypedSecrets", {
            path: encryptedPath,
            format: "json",
            types: { exportName: "TypedSecrets" },
          });

          return {
            topLevelKeys: file.topLevelKeys,
            types: file.types,
          };
        }),
      );
      yield* stack.destroy();

      expect(deployed.topLevelKeys).toEqual(["api", "enabled"]);
      expect(deployed.types).toContain("export interface TypedSecrets");
      expect(deployed.types).toContain(
        "readonly token: Redacted.Redacted<string>;",
      );
    }),
);

test.provider(
  "decrypts and merges ordered path arrays",
  (stack) =>
    Effect.gen(function* () {
      const commonPath = yield* writeEncryptedFixture("common.enc.json", "common-v1");
      const stagePath = yield* writeEncryptedFixture("stage.enc.json", "stage-v1");
      plaintextByPath.set(commonPath, () =>
        JSON.stringify({ api: { token: "common", baseUrl: "https://api" } }),
      );
      plaintextByPath.set(stagePath, () =>
        JSON.stringify({ api: { token: "stage" }, feature: { enabled: true } }),
      );

      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          const file = yield* SopsFile("MergedSecrets", {
            path: [commonPath, stagePath],
            format: "json",
            secrets: {
              token: "api.token",
              baseUrl: "api.baseUrl",
              enabled: "feature.enabled",
            },
          });

          return {
            path: file.path,
            topLevelKeys: file.topLevelKeys,
            token: Output.map(file.secrets, (secrets) => secrets.token!),
            baseUrl: Output.map(file.secrets, (secrets) => secrets.baseUrl!),
            enabled: Output.map(file.secrets, (secrets) => secrets.enabled!),
          };
        }),
      );
      yield* stack.destroy();

      expect(deployed.path).toBe([commonPath, stagePath].join(","));
      expect(deployed.topLevelKeys).toEqual(["api", "feature"]);
      expect(Redacted.value(deployed.token)).toBe("stage");
      expect(Redacted.value(deployed.baseUrl)).toBe("https://api");
      expect(Redacted.value(deployed.enabled)).toBe("true");
      expect(decryptCalls.get(commonPath)).toBe(1);
      expect(decryptCalls.get(stagePath)).toBe(1);
    }),
);

test.provider(
  "validates schema-backed contents and returns typed output",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "schema.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () =>
        JSON.stringify({
          api: { token: "first" },
          enabled: true,
        }),
      );

      const AppSecrets = Schema.Struct({
        api: Schema.Struct({
          token: Schema.RedactedFromValue(Schema.String),
        }),
        enabled: Schema.Boolean,
      });

      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          const file = yield* SopsFile("SchemaSecrets", {
            path: encryptedPath,
            format: "json",
            schema: AppSecrets,
          });
          type InferredValue =
            typeof file.value extends Output.Output<infer Value> ? Value : never;
          type _InferredValueIsNotAny = Expect<
            Equal<IsAny<InferredValue>, false>
          >;
          type _InferredValueMatchesSchema = Expect<
            Equal<InferredValue, Schema.Schema.Type<typeof AppSecrets>>
          >;

          return {
            token: Output.map(file.value, (secrets) => secrets.api.token),
            enabled: Output.map(file.value, (secrets) => secrets.enabled),
          };
        }),
      );
      yield* stack.destroy();

      expect(Redacted.value(deployed.token)).toBe("first");
      expect(deployed.enabled).toBe(true);
    }),
);

test.provider(
  "fails when schema-backed contents do not match",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "schema-invalid.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () =>
        JSON.stringify({
          api: { token: 42 },
        }),
      );

      const AppSecrets = Schema.Struct({
        api: Schema.Struct({
          token: Schema.String,
        }),
      });

      const failure = yield* stack
        .deploy(
          Effect.gen(function* () {
            yield* SopsFile("InvalidSchemaSecrets", {
              path: encryptedPath,
              format: "json",
              schema: AppSecrets,
            });
          }),
        )
        .pipe(Effect.flip);

      yield* stack.destroy();

      expect((failure as SopsSchemaError)._tag).toBe("SopsSchemaError");
      expect((failure as SopsSchemaError).message).toContain(
        "Failed to validate decrypted SOPS content",
      );
    }),
);

memoizedTest.provider(
  "memoizes duplicate decrypts during one provider run",
  (stack) =>
    Effect.gen(function* () {
      const encryptedPath = yield* writeEncryptedFixture(
        "memoized.enc.yaml",
        "ciphertext-v1",
      );
      plaintextByPath.set(encryptedPath, () => '{"token":"first"}');

      yield* stack.deploy(
        Effect.gen(function* () {
          const first = yield* SopsFile("FirstSecrets", {
            path: encryptedPath,
            format: "json",
            cache: false,
          });
          const second = yield* SopsFile("SecondSecrets", {
            path: encryptedPath,
            format: "json",
            cache: false,
          });

          return {
            first: Output.map(first.flat, (secrets) => secrets.token!),
            second: Output.map(second.flat, (secrets) => secrets.token!),
          };
        }),
      );
      yield* stack.destroy();

      expect(decryptCalls.get(encryptedPath)).toBe(1);
    }),
);

const writeEncryptedFixture = (filename: string, content: string) =>
  Effect.promise(async () => {
    const dir = join(import.meta.dir, ".tmp");
    const encryptedPath = join(dir, filename);
    decryptCalls.delete(encryptedPath);
    plaintextByPath.delete(encryptedPath);
    await mkdir(dir, { recursive: true });
    await writeFile(encryptedPath, content);
    return encryptedPath;
  });

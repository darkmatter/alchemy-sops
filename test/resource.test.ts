import { expect } from "bun:test";
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  SopsFile,
  SopsFileProvider,
  type SopsCommandRequest,
} from "../src/index.ts";

const decryptCalls = new Map<string, number>();
const plaintextByPath = new Map<string, () => string>();

const { test } = Test.make({
  providers: SopsFileProvider({
    decrypt: (request: SopsCommandRequest) =>
      Effect.sync(() => {
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

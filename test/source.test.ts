import { describe, expect, test } from "bun:test";
import * as Redacted from "effect/Redacted";

import { buildSopsCommandRequest } from "../src/source.ts";

describe("buildSopsCommandRequest", () => {
  test("normalizes resource and deployment-target defaults", () => {
    const ageKey = Redacted.make("AGE-SECRET-KEY-1example");
    const customEnv = Redacted.make("custom-value");
    const request = buildSopsCommandRequest({
      source: {
        path: "secrets.enc.json",
        content: "ciphertext",
      },
      options: {
        format: "auto",
        sopsBinary: Redacted.make("custom-sops"),
        sopsArgs: [Redacted.make("--verbose")],
        cwd: Redacted.make("/tmp/project"),
        extract: Redacted.make("[\"api\"]"),
        env: { CUSTOM_ENV: customEnv },
        ageKey,
        ageKeyFile: "keys.txt",
        timeoutMs: 1_000,
      },
    });

    expect(request).toMatchObject({
      path: "secrets.enc.json",
      content: "ciphertext",
      binary: "custom-sops",
      args: ["--verbose"],
      cwd: "/tmp/project",
      extract: "[\"api\"]",
      outputType: "json",
      timeoutMs: 1_000,
    });
    expect(request.inputType).toBeUndefined();
    expect(Redacted.isRedacted(request.env!.CUSTOM_ENV)).toBe(true);
    expect(Redacted.value(request.env!.CUSTOM_ENV as Redacted.Redacted<string>)).toBe(
      "custom-value",
    );
    expect(Redacted.value(request.env!.SOPS_AGE_KEY as Redacted.Redacted<string>)).toBe(
      "AGE-SECRET-KEY-1example",
    );
    expect(request.env!.SOPS_AGE_KEY_FILE).toBe("keys.txt");
  });

  test("keeps Config's input-format inference distinct", () => {
    const request = buildSopsCommandRequest({
      source: { content: "ciphertext" },
      options: { format: "yaml" },
      inferInputType: true,
    });

    expect(request.inputType).toBe("yaml");
    expect(request.outputType).toBe("yaml");
  });
});

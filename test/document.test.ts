import { describe, expect, test } from "bun:test";
import * as Redacted from "effect/Redacted";

import { materializeSecretDocument } from "../src/document.ts";

describe("materializeSecretDocument", () => {
  test("parses YAML and redacts every scalar leaf", () => {
    const result = materializeSecretDocument(
      "api:\n  token: sk_live\n  retries: 3\nenabled: true\n",
      {
        format: "yaml",
      },
    );

    expect(Redacted.isRedacted(result.flat["api.token"])).toBe(true);
    expect(Redacted.value(result.flat["api.token"]!)).toBe("sk_live");
    expect(Redacted.value(result.flat["api.retries"]!)).toBe("3");
    expect(Redacted.value(result.flat.enabled!)).toBe("true");
  });

  test("can expose a renamed subset of secrets", () => {
    const result = materializeSecretDocument('{"db":{"url":"postgres://db"}}', {
      format: "json",
      secrets: {
        DATABASE_URL: "db.url",
      },
    });

    expect(Object.keys(result.secrets)).toEqual(["DATABASE_URL"]);
    expect(Redacted.value(result.secrets.DATABASE_URL!)).toBe("postgres://db");
  });
});

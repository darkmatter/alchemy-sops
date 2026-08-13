import * as Redacted from "effect/Redacted";

/**
 * Public test-only identity for the encrypted demo document. Never use this
 * identity for an actual secret; each copied example should be re-encrypted.
 */
export const fixtureAgeKey = Redacted.make(
  "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH",
);

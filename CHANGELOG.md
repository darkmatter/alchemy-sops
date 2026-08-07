# Changelog

## 0.6.0 - 2026-08-07

### Added

- Added the Alchemy-free `alchemy-sops/Schema` entrypoint for decrypting imported
  SOPS JSON and decoding it with Effect Schema.
- Added `EncryptedFor<S>` so TypeScript checks encrypted document keys, nesting,
  optionality, and required SOPS metadata against the schema encoded type.
- Re-exported the Schema decoder from `alchemy-sops/edge`.

```ts
import * as Schema from "alchemy-sops/Schema";
import * as EffectSchema from "effect/Schema";
import encrypted from "./secrets.enc.json" with { type: "json" };

const AppSecrets = EffectSchema.Struct({
  token: EffectSchema.RedactedFromValue(EffectSchema.String),
});

const secrets = yield* Schema.decodeEffect(AppSecrets)(encrypted);
```

### Changed

- Made `alchemy` an optional peer so Effect applications can use the Schema and
  edge entrypoints without installing or resolving Alchemy.
- Kept `effect` as a required peer and removed unused Effect platform packages
  from runtime dependencies.
- Updated retry scheduling for the current Effect 4 Schedule API.

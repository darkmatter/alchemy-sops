# alchemy-sops

Alchemy Effect resource for decrypting SOPS files into redacted secret outputs.

`alchemy-sops` decrypts SOPS files, parses the decrypted document, and returns
Alchemy outputs whose scalar leaves are `Redacted<string>`. It prefers the
native `sops-age` backend for age-encrypted JSON/YAML/dotenv files and keeps the
`sops` CLI backend for binary files, custom SOPS flags, and non-age backends.

## Install

```sh
bun add alchemy-sops
```

The native backend does not require a `sops` binary. Install `sops` only when
you need `backend: "cli"` or automatic fallback for SOPS features not supported
by `sops-age`.

## Usage

```ts
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import { SopsFile, SopsFileProvider } from "alchemy-sops";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";

export default Alchemy.Stack(
  "App",
  {
    providers: SopsFileProvider(),
    state: Alchemy.localState(),
  },
  Effect.gen(function* () {
    const secrets = yield* SopsFile("Secrets", {
      path: "./secrets.enc.yaml",
      format: "yaml",
      ageKey: Config.redacted("SOPS_AGE_KEY"),
      secrets: {
        DATABASE_URL: "database.url",
        API_TOKEN: "api.token",
      },
    });

    return {
      sourceHash: secrets.sourceHash,
      databaseUrl: Output.map(secrets.secrets, (s) => s.DATABASE_URL),
    };
  }),
);
```

For local files, `backend: "auto"` is the default. It tries `sops-age` first for
structured age-encrypted files, then falls back to the CLI when a local `path`
source is available. Use `backend: "sops-age"` to require the native backend or
`backend: "cli"` to force the binary.

## Edge usage

Alchemy programs can avoid local filesystem and process APIs by using inline
encrypted content or a URL source with the native backend:

```ts
import { SopsFile } from "alchemy-sops";

const secrets = yield* SopsFile("WorkerSecrets", {
  content: encryptedSopsJson,
  format: "json",
  backend: "sops-age",
  ageKey: workerEnv.SOPS_AGE_KEY,
});
```

The Alchemy resource entrypoint still imports Alchemy. For code that is bundled
directly into an edge runtime, use the low-level `alchemy-sops/edge` subpath:

```ts
import { runSopsAge } from "alchemy-sops/edge";
```

## Inputs

Every string-like option accepts the same shapes as Alchemy `SecretInput`:

- `string`
- `Redacted<string>`
- `Effect<string | Redacted<string>>`
- `Config<string | Redacted<string>>`

Supported options:

- `path`, `content`, or `url`: exactly one encrypted source is required
- `cwd`, `sopsBinary`
- `backend`: `auto`, `sops-age`, or `cli`
- `format`: `auto`, `json`, `yaml`, `dotenv`, `text`, or `binary`
- `inputType`, `outputType`: input/output format hints
- `extract`: passed to `sops --extract` for CLI and as a key path for `sops-age`
- `sopsArgs`: extra CLI args; requires `backend: "cli"` or CLI fallback
- `env`, `ageKey`, `ageKeyFile`: SOPS environment inputs; `sops-age` uses
  direct `ageKey` / `SOPS_AGE_KEY`
- `secrets`: output-name to dot-path selectors
- `cache`, `timeoutMs`, `retry`

## Outputs

The resource returns:

- `data`: nested document with scalar leaves redacted
- `flat`: dot-path map of all redacted leaves
- `secrets`: selected redacted leaves, or all leaves when `secrets` is omitted
- `sourceHash`: SHA-256 digest of the encrypted source plus non-secret options
- `path`, `format`, `version`

`cache` defaults to `true`. If the encrypted source digest and resource version
are unchanged, the provider returns the previous redacted output without
decrypting again. Set `cache: false` to force decryption on every deploy.

## Security note

`Redacted<string>` prevents accidental printing and logging, but Alchemy state
stores still persist values so they can be revived later. Use a state store you
trust for decrypted secrets.

# alchemy-sops

Alchemy Effect resource for decrypting SOPS files into redacted secret outputs.

`alchemy-sops` shells out to `sops`, parses the decrypted document, and returns
Alchemy outputs whose scalar leaves are `Redacted<string>`.

## Install

```sh
bun add alchemy-sops
```

The package expects the `sops` CLI to be available on `PATH`, or you can pass
`sopsBinary`.

## Usage

```ts
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import { SopsFile, SopsFileProvider } from "alchemy-sops";
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

## Inputs

Every string-like option accepts the same shapes as Alchemy `SecretInput`:

- `string`
- `Redacted<string>`
- `Effect<string | Redacted<string>>`
- `Config<string | Redacted<string>>`

Supported options:

- `path`, `cwd`, `sopsBinary`
- `format`: `auto`, `json`, `yaml`, `dotenv`, `text`, or `binary`
- `inputType`, `outputType`: passed to `sops`
- `extract`: passed to `sops --extract`
- `sopsArgs`: extra CLI args
- `env`, `ageKey`, `ageKeyFile`: passed only to the child process environment
- `secrets`: output-name to dot-path selectors
- `cache`, `timeoutMs`, `retry`

## Outputs

The resource returns:

- `data`: nested document with scalar leaves redacted
- `flat`: dot-path map of all redacted leaves
- `secrets`: selected redacted leaves, or all leaves when `secrets` is omitted
- `sourceHash`: SHA-256 digest of the encrypted file plus non-secret options
- `path`, `format`, `version`

`cache` defaults to `true`. If the encrypted file digest and resource version
are unchanged, the provider returns the previous redacted output without running
`sops` again. Set `cache: false` to force decryption on every deploy.

## Security note

`Redacted<string>` prevents accidental printing and logging, but Alchemy state
stores still persist values so they can be revived later. Use a state store you
trust for decrypted secrets.

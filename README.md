# alchemy-sops

Alchemy Effect resource for decrypting SOPS files into redacted secret outputs.

`alchemy-sops` decrypts SOPS files, parses the decrypted document, and returns
Alchemy outputs whose scalar leaves are `Redacted<string>`. It prefers the
native `sops-age` backend for age-encrypted JSON/YAML/dotenv files and keeps the
`sops` CLI backend for binary files, custom SOPS flags, and non-age backends.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Cloudflare Secrets Store Action](#cloudflare-secrets-store-action)
- [Edge usage](#edge-usage)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Security note](#security-note)

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
    providers: SopsFileProvider({ memoize: true }),
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
      types: { exportName: "AppSecrets" },
    });

    return {
      sourceHash: secrets.sourceHash,
      topLevelKeys: secrets.topLevelKeys,
      types: secrets.types,
      databaseUrl: Output.map(secrets.secrets, (s) => s.DATABASE_URL),
    };
  }),
);
```

For local files, `backend: "auto"` is the default. It tries `sops-age` first for
structured age-encrypted files, then falls back to the CLI when a local `path`
source is available. Use `backend: "sops-age"` to require the native backend or
`backend: "cli"` to force the binary.

`SopsFileProvider({ memoize: true })` memoizes decrypt calls in the current
process. This is useful when multiple lazy resource paths request the same
encrypted source during one deploy. It does not replace resource `cache`; `cache`
controls persisted Alchemy output reuse across deploys.

Successful decrypts log the top-level keys without logging values. Set
`types: true` or `types: { exportName: "AppSecrets" }` to return generated
TypeScript definitions in `secrets.types`; no files are written.

## Cloudflare Secrets Store Action

Use `CloudflareSopsSecrets` when Cloudflare Workers should receive secrets from
Cloudflare Secrets Store instead of Alchemy state. It is the high-level wrapper
around the exported `CloudflareSopsSecretsAction`.

The wrapper reads a local encrypted SOPS file before registering the Action,
passes ciphertext into Action state, decrypts during deploy, and imports selected
values into the target store. Plaintext is sent to Cloudflare Secrets Store but
is not persisted as Action input.

A stack using the Action needs:

- Cloudflare providers and state configured in the Alchemy stack
- A `Cloudflare.SecretsStore` resource or `{ accountId, storeId }` reference
- A deploy-time SOPS identity, preferably passed as `Redacted<string>`
- A `secrets` map from Cloudflare secret names to decrypted dot-path selectors,
  or no `secrets` map when all scalar leaves should be imported

```ts
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import {
  CloudflareSopsSecrets,
  cloudflareSopsWorkerBindings,
} from "alchemy-sops";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

export default Alchemy.Stack(
  "Worker",
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const store = yield* Cloudflare.SecretsStore("Secrets");

    const imported = yield* CloudflareSopsSecrets("WorkerSecrets", {
      path: "./secrets.enc.yaml",
      format: "yaml",
      backend: "sops-age",
      store,
      ageKey: Redacted.make(process.env.SOPS_AGE_KEY!),
      scopes: ["workers"],
      comment: "imported by alchemy-sops",
      secrets: {
        API_TOKEN: "api.token",
        DATABASE_URL: "database.url",
      },
    });

    const worker = yield* Cloudflare.Worker("Api", {
      main: "./src/worker.ts",
    });
    yield* worker.bind(
      "sops-secrets",
      cloudflareSopsWorkerBindings(imported, [
        "API_TOKEN",
        "DATABASE_URL",
      ]),
    );

    return {
      url: worker.url,
    };
  }),
);
```

`secrets` maps Cloudflare secret names to paths in the decrypted document. Omit
it to import every scalar leaf; generated names are derived from dot paths, and
`namePrefix` can add a prefix to every generated name.

`cloudflareSopsWorkerBindings(imported, ["API_TOKEN"])` binds a Worker variable
to the Secrets Store secret with the same name. Pass an object when the Worker
binding name should differ from the stored secret name:

```ts
yield* worker.bind(
  "sops-secrets",
  cloudflareSopsWorkerBindings(imported, {
    API_TOKEN: "WORKER_API_TOKEN",
  }),
);
```

Run the stack with your normal Alchemy deploy command. The Action runs when its
input changes, including the encrypted file content, backend options, selected
secret paths, scopes, comments, and target store.

Existing Secrets Store entries are replaced by default because Cloudflare does
not allow patching a secret value. Set `replaceExisting: false` when you only
want to converge scopes and comments for an existing secret name. The Cloudflare
credentials used by the stack must be allowed to manage the target Secrets
Store, and Worker deploy permissions are also needed when the same stack binds
those secrets to a Worker.

Most stacks should call `CloudflareSopsSecrets`. Use
`CloudflareSopsSecretsAction` directly only when the encrypted content is
already available and you want to pass the Action input yourself:

```ts
import { CloudflareSopsSecretsAction } from "alchemy-sops";
import * as Redacted from "effect/Redacted";

const imported = yield* CloudflareSopsSecretsAction("WorkerSecrets", {
  path: "secrets.enc.yaml",
  content: encryptedSopsYaml,
  format: "yaml",
  backend: "sops-age",
  store: {
    accountId: "account-id",
    storeId: "store-id",
  },
  ageKey: Redacted.make(process.env.SOPS_AGE_KEY!),
  secrets: {
    API_TOKEN: "api.token",
  },
});
```

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
- `types`: return generated TypeScript definitions for the redacted data shape;
  use `true` or `{ exportName: "AppSecrets" }`
- `cache`, `timeoutMs`, `retry`

Provider options:

- `decrypt`: custom decrypt backend
- `memoize`: `true` to share in-flight and completed decrypts by request in the
  current process, or `{ key }` to provide a custom memoization key

`CloudflareSopsSecrets` shares the decrypt options above and adds:

- `store`: Cloudflare Secrets Store resource or `{ accountId, storeId }`
- `namePrefix`: prefix for generated Cloudflare secret names when `secrets` is
  omitted
- `scopes`: Cloudflare Secrets Store scopes; defaults to `["workers"]`
- `comment`: free-form Cloudflare Secrets Store comment
- `replaceExisting`: delete and recreate matching existing secrets so values
  converge; defaults to `true`

`CloudflareSopsSecretsAction` also accepts `content`, the encrypted SOPS
ciphertext to use as Action input. The `CloudflareSopsSecrets` wrapper fills
that field by reading `path`.

## Outputs

The resource returns:

- `data`: nested document with scalar leaves redacted
- `flat`: dot-path map of all redacted leaves
- `secrets`: selected redacted leaves, or all leaves when `secrets` is omitted
- `topLevelKeys`: top-level keys from the decrypted document
- `types`: generated TypeScript definitions when `types` was requested
- `sourceHash`: SHA-256 digest of the encrypted source plus non-secret options
- `path`, `format`, `version`

`cache` defaults to `true`. If the encrypted source digest and resource version
are unchanged, the provider returns the previous redacted output without
decrypting again. Set `cache: false` to force decryption on every deploy.

The Cloudflare Action returns `accountId`, `storeId`, `path`, and an `imported`
array containing each Cloudflare secret name, source dot path, secret id, and
status.

## Security note

`Redacted<string>` prevents accidental printing and logging, but Alchemy state
stores still persist values so they can be revived later. Use a state store you
trust for decrypted secrets.

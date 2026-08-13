# Examples

Every directory is a runnable, focused use case. The shared encrypted fixture
uses a public test-only age identity so the smoke suite can prove decryption;
copy the code, but always encrypt your own document and use your own identity.

| Example | Use it when | Run it locally |
| --- | --- | --- |
| [`sops-file`](./sops-file) | An Alchemy stack needs selected redacted SOPS values. | `SOPS_AGE_KEY=... bun alchemy deploy examples/sops-file/alchemy.run.ts` |
| [`json-import`](./json-import) | An encrypted JSON import should drive `secrets.data` types. | `SOPS_AGE_KEY=... bun alchemy deploy examples/json-import/alchemy.run.ts` |
| [`schema-decoder`](./schema-decoder) | A non-Alchemy Effect program needs validated SOPS JSON. | `SOPS_AGE_KEY=... bun examples/schema-decoder/main.ts` |
| [`config-provider`](./config-provider) | Effect configuration—including provider credentials—should resolve from SOPS. | `SOPS_AGE_KEY=... bun examples/config-provider/main.ts` |
| [`cloudflare-secrets-store`](./cloudflare-secrets-store) | SOPS values belong in Cloudflare Secrets Store. | `CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_SECRETS_STORE_ID=... SOPS_AGE_KEY=... bun alchemy deploy examples/cloudflare-secrets-store/alchemy.run.ts` |
| [`github-actions-secrets`](./github-actions-secrets) | SOPS values should become repository or environment GitHub Actions secrets. | `GITHUB_OWNER=... GITHUB_REPOSITORY=... SOPS_AGE_KEY=... bun alchemy deploy examples/github-actions-secrets/alchemy.run.ts` |

The Cloudflare and GitHub examples require their usual Alchemy credentials. The
GitHub token needs `repo` for private repositories or `public_repo` for public
ones. Set `GITHUB_ENVIRONMENT` to scope the GitHub secret to an Actions
environment; omit it for a repository secret.

## Smoke checks

```sh
bun run build
bun run smoke:examples
```

`examples/smoke.test.ts` runs in CI after the package build. It decrypts the
shared fixture for every SOPS entry point and uses local mock APIs to prove the
Cloudflare and GitHub examples make the expected secret-management requests.

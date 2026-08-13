import * as Effect from "effect/Effect";

import { requiredEnvironment } from "../_shared/env.ts";
import { readSecrets } from "./app.ts";

const secrets = await Effect.runPromise(
  readSecrets(requiredEnvironment("SOPS_AGE_KEY")),
);

console.log(
  JSON.stringify({
    enabled: secrets.api.enabled,
    retryCount: secrets.nested.count,
  }),
);

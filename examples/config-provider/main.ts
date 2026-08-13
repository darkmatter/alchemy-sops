import * as Effect from "effect/Effect";

import { requiredEnvironment } from "../_shared/env.ts";
import { readAppConfig } from "./app.ts";

const config = await Effect.runPromise(
  readAppConfig(requiredEnvironment("SOPS_AGE_KEY")),
);

console.log(JSON.stringify({ retryCount: config.retryCount }));

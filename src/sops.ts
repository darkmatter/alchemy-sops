import * as Effect from "effect/Effect";

import { SopsDecryptError } from "./errors.js";
import { requestLabel, type SopsDecrypt } from "./decrypt.js";

export {
  buildSopsArgs,
  revealEnv,
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";

export const runSopsCli: SopsDecrypt = (request) =>
  Effect.flatMap(
    Effect.tryPromise({
      try: () => import("./sops-cli.js"),
      catch: (cause) =>
        new SopsDecryptError({
          message: "Failed to load the sops CLI backend",
          path: requestLabel(request),
          cause,
        }),
    }),
    ({ runSopsCli }) => runSopsCli(request),
  );

export { runSopsAge } from "./sops-age.js";

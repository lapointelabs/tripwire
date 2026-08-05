import { createRequire } from "node:module";

// Read from package.json rather than keeping a second copy here. A hard-coded literal can
// drift from the manifest, which means the CLI reports a version the package does not have.
export const VERSION = createRequire(import.meta.url)("../package.json").version;

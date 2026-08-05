import { readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";

const roots = ["bin", "src", "scripts", "test"];
const files = [];

async function visit(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) await visit(target);
    else if (entry.isFile() && target.endsWith(".js")) files.push(target);
  }
}

for (const root of roots) await visit(root);
for (const file of files.sort()) {
  const checked = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (checked.status !== 0) {
    process.stderr.write(checked.stderr || checked.stdout);
    process.exitCode = 1;
  }
}

if (process.exitCode) process.stderr.write(`Syntax check failed.\n`);
else process.stdout.write(`Syntax OK: ${files.length} JavaScript files.\n`);

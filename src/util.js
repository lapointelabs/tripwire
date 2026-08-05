import { createHash } from "node:crypto";
import { access, readFile, readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

export const REPORT_DIR = ".tripwire";

/**
 * Where scan artifacts go when the caller did not say.
 *
 * Deliberately outside the repository. A scanner that drops files into the tree it is
 * scanning shows up in `git status`, needs a `.gitignore` entry, gets committed by
 * accident, and — worst for this tool — becomes input to its own next scan. Keying the
 * directory by a hash of the project path keeps runs for different projects apart while
 * staying stable across runs, so "re-read the last fix plan" works.
 */
export function artifactDirFor(projectDirectory) {
  const base = process.env.XDG_CACHE_HOME
    || (process.platform === "darwin" ? path.join(homedir(), "Library", "Caches") : path.join(homedir(), ".cache"));
  const slug = path.basename(projectDirectory).replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 40) || "project";
  const digest = createHash("sha256").update(path.resolve(projectDirectory)).digest("hex").slice(0, 8);
  return path.join(base, "tripwire", `${slug}-${digest}`);
}

const DEFAULT_IGNORES = new Set([
  ".git", ".hg", ".svn", ".tripwire", "node_modules", "bower_components", "vendor",
  "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache",
  "coverage", ".nyc_output", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
  ".pytest_cache", "bin", "obj", "target", ".gradle", ".idea", ".vscode", ".cache",
  "Pods", "DerivedData", ".terraform", ".serverless", "site-packages"
]);

// Extensions we can meaningfully reason about. Everything else is skipped before it is read.
export const SOURCE_EXTENSIONS = new Map([
  [".js", "javascript"], [".jsx", "javascript"], [".mjs", "javascript"], [".cjs", "javascript"],
  [".ts", "typescript"], [".tsx", "typescript"], [".mts", "typescript"], [".cts", "typescript"],
  [".vue", "vue"], [".svelte", "svelte"],
  [".py", "python"], [".pyi", "python"],
  [".cs", "csharp"], [".cshtml", "csharp"], [".razor", "csharp"],
  [".go", "go"], [".rb", "ruby"], [".php", "php"], [".java", "java"], [".kt", "kotlin"],
  [".rs", "rust"], [".sql", "sql"], [".sh", "shell"], [".bash", "shell"],
  [".md", "markdown"], [".mdc", "markdown"], [".mdx", "markdown"],
  [".yml", "yaml"], [".yaml", "yaml"], [".json", "json"], [".toml", "toml"], [".env", "dotenv"]
]);

const MAX_FILE_BYTES = 1_500_000;

export async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function readJson(filePath) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch {
    return null;
  }
}

export async function readText(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

export function toPosix(value) {
  return value.split(path.sep).join("/");
}

export function relativePath(root, absolutePath) {
  return toPosix(path.relative(root, absolutePath)) || ".";
}

export function languageOf(filePath) {
  return SOURCE_EXTENSIONS.get(path.extname(filePath).toLowerCase()) || null;
}

/**
 * Parse a `.gitignore`-style file into matcher functions. This is deliberately a
 * subset of the real spec: leading `!` negation, directory-only `/` suffixes, and
 * `*` / `**` globs. Anything more exotic is treated as a literal substring, which
 * over-includes rather than silently hiding files from the scan.
 */
// Sentinel standing in for `**` while single-star globs are expanded, chosen so it
// cannot collide with any character a real path pattern contains.
const SEGMENT_WILDCARD = "\u0000";

export function compileIgnorePatterns(text) {
  const rules = [];
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    let pattern = negated ? line.slice(1) : line;
    const directoryOnly = pattern.endsWith("/");
    if (directoryOnly) pattern = pattern.slice(0, -1);
    const anchored = pattern.startsWith("/");
    if (anchored) pattern = pattern.slice(1);
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, SEGMENT_WILDCARD)
      .replace(/\*/g, "[^/]*")
      .split(SEGMENT_WILDCARD).join(".*")
      .replace(/\?/g, "[^/]");
    const source = anchored ? `^${escaped}(/|$)` : `(^|/)${escaped}(/|$)`;
    rules.push({ negated, directoryOnly, regex: new RegExp(source) });
  }
  return rules;
}

export function isIgnored(rules, relative, isDirectory) {
  let ignored = false;
  for (const rule of rules) {
    if (rule.directoryOnly && !isDirectory) continue;
    if (!rule.regex.test(relative)) continue;
    ignored = !rule.negated;
  }
  return ignored;
}

/**
 * Walk a directory tree and yield scannable source files. Symlinks are not followed:
 * a scanner that chases links can be pointed outside the repository by the repository
 * it is scanning.
 */
export async function walkSourceFiles(root, options = {}) {
  const ignoreRules = options.ignoreRules || [];
  const extraIgnores = new Set(options.extraIgnores || []);
  const limit = options.limit || Infinity;
  const files = [];

  async function visit(directory) {
    if (files.length >= limit) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= limit) return;
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      const relative = relativePath(root, absolute);
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORES.has(entry.name) || extraIgnores.has(entry.name)) continue;
        if (isIgnored(ignoreRules, relative, true)) continue;
        await visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!languageOf(entry.name)) continue;
      if (isIgnored(ignoreRules, relative, false)) continue;
      let info;
      try {
        info = await stat(absolute);
      } catch {
        continue;
      }
      if (info.size > MAX_FILE_BYTES || info.size === 0) continue;
      files.push({ absolute, relative, language: languageOf(entry.name), bytes: info.size });
    }
  }

  await visit(root);
  files.sort((a, b) => a.relative.localeCompare(b.relative));
  return files;
}

export function parseArgs(args) {
  const booleanFlags = new Set([
    "help", "version", "json", "yes", "no-ai", "ai", "quiet", "verbose", "list", "all",
    "no-color", "score", "force", "audit", "offline"
  ]);
  const positionals = [];
  const flags = {};
  for (let index = 0; index < args.length; index += 1) {
    const item = args[index];
    if (item === "--") {
      positionals.push(...args.slice(index + 1));
      break;
    }
    if (!item.startsWith("--")) {
      positionals.push(item);
      continue;
    }
    const body = item.slice(2);
    const equals = body.indexOf("=");
    if (equals !== -1) {
      addFlag(flags, body.slice(0, equals), body.slice(equals + 1));
      continue;
    }
    if (booleanFlags.has(body)) {
      addFlag(flags, body, true);
      continue;
    }
    const next = args[index + 1];
    if (next === undefined || next.startsWith("--")) {
      addFlag(flags, body, true);
      continue;
    }
    addFlag(flags, body, next);
    index += 1;
  }
  return { positionals, flags };
}

function addFlag(flags, name, value) {
  if (name in flags) {
    flags[name] = [].concat(flags[name], value);
    return;
  }
  flags[name] = value;
}

export function flag(flags, name, fallback = undefined) {
  const value = flags[name];
  if (value === undefined) return fallback;
  return Array.isArray(value) ? value[value.length - 1] : value;
}

export function flagList(flags, name) {
  const value = flags[name];
  if (value === undefined) return [];
  return [].concat(value).filter((item) => typeof item === "string");
}

const COLORS = {
  reset: "\u001b[0m", bold: "\u001b[1m", dim: "\u001b[2m",
  red: "\u001b[31m", yellow: "\u001b[33m", green: "\u001b[32m",
  blue: "\u001b[34m", magenta: "\u001b[35m", cyan: "\u001b[36m", gray: "\u001b[90m"
};

export function createPalette(enabled) {
  const active = enabled && process.stdout.isTTY && !process.env.NO_COLOR;
  const paint = (code) => (value) => (active ? `${code}${value}${COLORS.reset}` : String(value));
  return {
    enabled: active,
    bold: paint(COLORS.bold), dim: paint(COLORS.dim), red: paint(COLORS.red),
    yellow: paint(COLORS.yellow), green: paint(COLORS.green), blue: paint(COLORS.blue),
    magenta: paint(COLORS.magenta), cyan: paint(COLORS.cyan), gray: paint(COLORS.gray)
  };
}

export function pluralize(count, singular, plural = `${singular}s`) {
  return count === 1 ? singular : plural;
}

/** Run tasks with bounded concurrency so a large repository cannot exhaust file handles. */
export async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = new Array(Math.min(limit, items.length || 1)).fill(null).map(async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

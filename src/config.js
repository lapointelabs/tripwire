import path from "node:path";
import { ENGINES } from "./engines/catalog.js";
import { readJson } from "./util.js";

/**
 * One config file, because the alternative is five.
 *
 * Assembling this stack by hand means a `.semgrepignore`, a TruffleHog exclusion file, an
 * osv-scanner config, a Snyk policy, and an agnix config — five files, five schemas, five
 * places to look when a finding you suppressed comes back. Collapsing that is most of the
 * reason to run the engines through one harness rather than five CI steps.
 *
 * Config is optional in every case. Tripwire runs with none, and every value here has a
 * working default; the file exists to pin choices, not to make the tool usable.
 */

const FILENAMES = ["tripwire.config.json", ".tripwire.json"];

const SCAN_KEYS = new Set(["engines", "offline", "failOn", "only", "skip", "provider", "model", "budget", "audit", "out"]);

/**
 * Load config from the project root.
 *
 * Unknown keys are returned as warnings rather than ignored or thrown on. A typo in a
 * config file that silently does nothing is how people conclude a setting does not work.
 */
export async function loadConfig(root) {
  for (const filename of FILENAMES) {
    const file = path.join(root, filename);
    const raw = await readJson(file);
    if (!raw) continue;
    const { config, warnings } = normalize(raw);
    return { ...config, file, filename, warnings };
  }
  return { engines: {}, scan: {}, file: null, filename: null, warnings: [] };
}

function normalize(raw) {
  const warnings = [];
  const engines = {};

  for (const [id, value] of Object.entries(raw.engines || {})) {
    if (!ENGINES.some((engine) => engine.id === id)) {
      warnings.push(`unknown engine "${id}" — run \`tripwire engines\` for the list`);
      continue;
    }
    if (value === false) {
      engines[id] = { enabled: false };
      continue;
    }
    if (value === true) {
      engines[id] = { enabled: true };
      continue;
    }
    if (typeof value !== "object" || value === null) {
      warnings.push(`engine "${id}" expects an object, true, or false`);
      continue;
    }
    engines[id] = {
      enabled: value.enabled !== false,
      config: value.config,
      // Extra arguments are appended after Tripwire's own, so a user can pass an exclusion
      // file or a ruleset the adapter does not model. They cannot remove what Tripwire
      // set — notably the JSON output flag the parser depends on.
      args: Array.isArray(value.args) ? value.args.map(String) : [],
      env: typeof value.env === "object" && value.env ? value.env : undefined,
      limit: Number.isInteger(value.limit) ? value.limit : undefined,
      timeoutMs: Number.isInteger(value.timeoutMs) ? value.timeoutMs : undefined
    };
  }

  const scan = {};
  for (const [key, value] of Object.entries(raw.scan || {})) {
    if (!SCAN_KEYS.has(key)) {
      warnings.push(`unknown scan option "${key}"`);
      continue;
    }
    scan[key] = value;
  }

  for (const key of Object.keys(raw)) {
    if (key !== "engines" && key !== "scan" && key !== "$schema") {
      warnings.push(`unknown top-level key "${key}" — expected "engines" or "scan"`);
    }
  }

  return { config: { engines, scan }, warnings };
}

/**
 * Resolve which engines to run from the flag and the config file.
 *
 * `auto` — every installed engine that the config has not disabled. This is the default
 * when `--engines` is passed without a value, and it is the behaviour that makes the
 * one-stop claim true: install what you want, and it is in the scan.
 */
export function resolveSelection(value, config) {
  if (value === undefined || value === null || value === false) {
    return config.scan?.engines ? resolveSelection(config.scan.engines, { ...config, scan: {} }) : "none";
  }
  if (value === true || value === "auto") return "auto";
  if (Array.isArray(value)) return value.flatMap((item) => String(item).split(/[,\s]+/)).filter(Boolean);

  const text = String(value).trim().toLowerCase();
  if (text === "none" || text === "off" || text === "false") return "none";
  if (text === "all") return "all";
  if (text === "auto" || text === "true") return "auto";
  return text.split(/[,\s]+/).filter(Boolean);
}

/** Names in a selection that match no known engine, so a typo is reported rather than silent. */
export function unknownEngines(selection) {
  if (!Array.isArray(selection)) return [];
  return selection.filter((id) => !ENGINES.some((engine) => engine.id === id));
}

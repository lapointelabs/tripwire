import { spawn } from "node:child_process";

/**
 * Running other people's tools.
 *
 * Tripwire delegates whole domains to whatever the ecosystem already does better than a
 * generalist scanner could — advisory databases, secret verification, deep dataflow. That
 * makes subprocess handling load-bearing rather than incidental, so it lives in one place
 * with one set of guarantees:
 *
 *   - An argument array, never a shell. This tool reports command injection; it must not
 *     introduce one by interpolating a project path into a shell string.
 *   - A timeout that actually kills. A hung scanner in CI is worse than a missing one.
 *   - Never throws. A missing binary, a bad key, or a garbage payload degrades to a stated
 *     reason, because the deterministic scan is the product and this is an addition to it.
 */

export const DEFAULT_TIMEOUT_MS = 120_000;

/** Output past this is a runaway tool, not a result. Held in memory, so it is bounded. */
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/**
 * Spawn a tool and collect its output.
 *
 * Resolves `{ ok: false, reason }` for anything that stopped the tool from producing
 * output, and `{ ok: true, code, stdout, stderr }` otherwise — including a non-zero exit,
 * because scanners exit non-zero *because* they found something. The exit code says
 * nothing about whether the run succeeded; parsable output is the real signal.
 */
export function runTool({ command, args = [], cwd, timeoutMs = DEFAULT_TIMEOUT_MS, env }) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
        // Inherit the caller's environment so a tool finds its own config and credential
        // store, with only the keys this engine declared layered on top.
        env: env ? { ...process.env, ...env } : process.env
      });
    } catch (error) {
      resolve({ ok: false, reason: error.message });
      return;
    }

    let stdout = "";
    let stderr = "";
    let bytes = 0;
    let settled = false;

    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({ ok: false, reason: `${command} timed out after ${Math.round(timeoutMs / 1000)}s`, timedOut: true });
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish({ ok: false, reason: `${command} produced more than ${MAX_OUTPUT_BYTES / 1024 / 1024}MB of output` });
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => { stderr += chunk; });

    child.on("error", (error) => {
      finish({ ok: false, reason: error.code === "ENOENT" ? `${command} is not installed` : error.message, missing: error.code === "ENOENT" });
    });
    child.on("close", (code) => {
      finish({ ok: true, code, stdout, stderr });
    });
  });
}

/** Whether a command exists, without running it for real. */
export async function toolExists(command) {
  const probe = process.platform === "win32" ? "where" : "which";
  const result = await runTool({ command: probe, args: [command], timeoutMs: 5_000 });
  return Boolean(result.ok && result.code === 0 && result.stdout.trim());
}

/** One JSON document, tolerating a human line printed before the body. */
export function parseJson(text) {
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    const start = text.search(/[[{]/);
    if (start === -1) return null;
    const open = text[start];
    const end = text.lastIndexOf(open === "{" ? "}" : "]");
    if (end <= start) return null;
    try {
      return JSON.parse(text.slice(start, end + 1));
    } catch {
      return null;
    }
  }
}

/**
 * One JSON value per line. TruffleHog and several other scanners stream results this way
 * so a consumer can act on the first hit without waiting for the run to finish — which
 * also means the stream is interleaved with log lines that are not JSON at all.
 */
export function parseNdjson(text) {
  const values = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed[0] !== "{") continue;
    try {
      values.push(JSON.parse(trimmed));
    } catch {
      // A log line that happens to start with a brace, or a truncated final write.
    }
  }
  return values;
}

/**
 * Split a stream of concatenated top-level JSON values.
 *
 * `govulncheck -json` emits a sequence of pretty-printed objects rather than one document
 * or one-per-line, so neither `JSON.parse` nor splitting on newlines reads it. Brace
 * matching that skips over string contents does, without pulling in a streaming parser.
 */
export function parseJsonStream(text) {
  const values = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      continue;
    }
    if (char === "{") {
      if (depth === 0) start = index;
      depth += 1;
      continue;
    }
    if (char === "}") {
      depth -= 1;
      if (depth === 0 && start !== -1) {
        try {
          values.push(JSON.parse(text.slice(start, index + 1)));
        } catch {
          // A truncated trailing object is expected when a tool is killed; skip it.
        }
        start = -1;
      }
    }
  }
  return values;
}

/** The first non-empty line of stderr, for reporting why a tool declined to run. */
export function firstLine(text, limit = 200) {
  const line = String(text || "").split("\n").map((value) => value.trim()).find(Boolean);
  return line ? line.slice(0, limit) : "";
}

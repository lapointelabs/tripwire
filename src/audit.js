import { spawn } from "node:child_process";
import path from "node:path";
import { exists, readJson } from "./util.js";

/**
 * Dependency vulnerability auditing, delegated to each ecosystem's own tool.
 *
 * Tripwire's supply-chain rules ask whether the defenses are in place. They cannot tell
 * you that the version you pinned has a known advisory, and building that would mean
 * shipping and refreshing a vulnerability database — badly, and always slightly stale.
 * `npm audit`, `dotnet list package --vulnerable`, `pip-audit`, `govulncheck` and
 * `cargo audit` already do it, against feeds their ecosystems maintain.
 *
 * So Tripwire runs them and normalizes the output into ordinary findings.
 *
 * This is opt-in (`--audit`) because it is the only part of a scan that spawns a
 * subprocess and reaches the network. A scanner that quietly makes network calls is a
 * scanner people cannot run on an air-gapped build agent, and surprising them once is
 * enough to lose the tool. When it has not run, the report says so rather than leaving
 * a clean-looking silence.
 */

const TIMEOUT_MS = 120_000;

/** Severity as each ecosystem reports it, mapped onto Tripwire's four levels. */
const SEVERITY = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  medium: "medium",
  low: "low",
  info: "low",
  unknown: "medium"
};

/**
 * The finding shape for an externally sourced advisory. It is a rule in every sense the
 * report cares about — it has a title, a rationale, and a fix — but it never runs against
 * source, so it lives outside the scanning rule sets.
 */
export const VULNERABLE_DEPENDENCY_RULE = {
  id: "supply-chain/vulnerable-dependency",
  category: "supply-chain",
  severity: "high",
  title: "Dependency with a known vulnerability",
  why: "A published advisory means the weakness is documented, indexed, and reachable by anyone scanning for it — the exploit is often public before the upgrade lands. Transitive dependencies count: the code runs with your process's privileges regardless of who chose it.",
  fix: "Upgrade to a fixed version. Where none exists, check whether the vulnerable path is reachable from your code before treating it as urgent, and record that reasoning somewhere durable — an advisory nobody can re-derive gets re-triaged from scratch every quarter.",
  languages: "*",
  requires: null,
  confidence: "high",
  external: true
};

function run(command, args, cwd) {
  return new Promise((resolve) => {
    let child;
    try {
      // Argument array, never a shell — this tool reports command injection; it should
      // not introduce one by interpolating a project path into a shell string.
      child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      resolve({ ok: false, reason: error.message });
      return;
    }

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ ok: false, reason: `${command} timed out after ${TIMEOUT_MS / 1000}s` });
    }, TIMEOUT_MS);

    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ ok: false, reason: error.code === "ENOENT" ? `${command} is not installed` : error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      // Audit tools exit non-zero *because* they found something, so the exit code says
      // nothing about whether the run succeeded. Parsable output is the real signal.
      resolve({ ok: true, code, stdout, stderr });
    });
  });
}

function parseJson(text) {
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    // Some tools print a human line before the JSON body.
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start === -1 || end <= start) return null;
    try {
      return JSON.parse(text.slice(start, end + 1));
    } catch {
      return null;
    }
  }
}

/** npm 7+ `vulnerabilities` map, and the older `advisories` map pnpm still emits. */
function fromNpm(payload) {
  const found = [];
  for (const [name, entry] of Object.entries(payload?.vulnerabilities || {})) {
    const advisories = (entry.via || []).filter((via) => typeof via === "object");
    found.push({
      package: name,
      severity: SEVERITY[entry.severity] || "medium",
      range: entry.range,
      dev: Boolean(entry.isDirect === false && entry.effects?.length === 0 && entry.dev),
      fix: entry.fixAvailable === true ? "an upgrade is available"
        : entry.fixAvailable?.name ? `upgrade ${entry.fixAvailable.name} to ${entry.fixAvailable.version}`
          : "no fixed version published",
      ids: advisories.map((via) => via.url || via.source).filter(Boolean).slice(0, 3),
      title: advisories[0]?.title || null
    });
  }
  for (const entry of Object.values(payload?.advisories || {})) {
    found.push({
      package: entry.module_name,
      severity: SEVERITY[entry.severity] || "medium",
      range: entry.vulnerable_versions,
      fix: entry.patched_versions && entry.patched_versions !== "<0.0.0"
        ? `upgrade to ${entry.patched_versions}` : "no fixed version published",
      ids: [entry.url].filter(Boolean),
      title: entry.title || null
    });
  }
  return found;
}

function fromDotnet(payload) {
  const found = [];
  for (const project of payload?.projects || []) {
    for (const framework of project.frameworks || []) {
      for (const kind of ["topLevelPackages", "transitivePackages"]) {
        for (const entry of framework[kind] || []) {
          for (const vulnerability of entry.vulnerabilities || []) {
            found.push({
              package: entry.id,
              version: entry.resolvedVersion,
              severity: SEVERITY[String(vulnerability.severity).toLowerCase()] || "medium",
              transitive: kind === "transitivePackages",
              fix: "upgrade to a version outside the advisory range",
              ids: [vulnerability.advisoryurl].filter(Boolean),
              title: null
            });
          }
        }
      }
    }
  }
  return found;
}

function fromPipAudit(payload) {
  const entries = Array.isArray(payload) ? payload : payload?.dependencies || [];
  const found = [];
  for (const entry of entries) {
    for (const vulnerability of entry.vulns || entry.vulnerabilities || []) {
      found.push({
        package: entry.name,
        version: entry.version,
        severity: SEVERITY[String(vulnerability.severity || "unknown").toLowerCase()] || "medium",
        fix: vulnerability.fix_versions?.length ? `upgrade to ${vulnerability.fix_versions[0]}` : "no fixed version published",
        ids: [vulnerability.id].filter(Boolean),
        title: (vulnerability.description || "").split(/[.\n]/)[0] || null
      });
    }
  }
  return found;
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

/**
 * govulncheck reports two tiers, and the distinction is the reason to run it: a module
 * can contain a vulnerable function you never call. Findings carrying a function in their
 * trace are reachable from this code; the rest are present but not exercised. Reporting
 * both at the same severity would bury the ones that actually matter.
 */
export function fromGovulncheck(messages) {
  const advisories = new Map();
  for (const message of messages) {
    if (!message.osv) continue;
    const osv = message.osv;
    advisories.set(osv.id, {
      id: osv.id,
      summary: osv.summary || osv.details?.split(/[.\n]/)[0] || null,
      package: osv.affected?.[0]?.package?.name || osv.affected?.[0]?.module || osv.id,
      aliases: osv.aliases || []
    });
  }

  const byId = new Map();
  for (const message of messages) {
    const finding = message.finding;
    if (!finding?.osv) continue;
    const trace = finding.trace || [];
    const called = trace.some((frame) => frame.function);
    const existing = byId.get(finding.osv);
    byId.set(finding.osv, {
      called: called || Boolean(existing?.called),
      fixed: finding.fixed_version || existing?.fixed || null,
      module: trace[0]?.module || existing?.module || null
    });
  }

  const found = [];
  for (const [id, detail] of byId) {
    const advisory = advisories.get(id) || { id, summary: null, package: id, aliases: [] };
    found.push({
      package: detail.module || advisory.package,
      severity: detail.called ? "high" : "low",
      // The CVE alias is what people search for; the GO id is what govulncheck reports.
      ids: [`https://pkg.go.dev/vuln/${id}`],
      title: [
        advisory.summary,
        detail.called ? null : "not reachable from this code — the vulnerable function is never called"
      ].filter(Boolean).join(" — ") || null,
      fix: detail.fixed ? `upgrade to ${detail.fixed}` : "no fixed version published"
    });
  }
  return found;
}

/**
 * cargo-audit separates advisories from warnings. RustSec entries carry a CVSS vector
 * rather than a computed score, so rather than invent a severity this maps vulnerabilities
 * to high and informational warnings — unmaintained, unsound — to low, and names the
 * advisory so the real rating is one lookup away.
 */
export function fromCargoAudit(payload) {
  const found = [];
  for (const entry of payload?.vulnerabilities?.list || []) {
    const advisory = entry.advisory || {};
    found.push({
      package: entry.package?.name || advisory.package || "unknown",
      version: entry.package?.version,
      severity: "high",
      fix: entry.versions?.patched?.length ? `upgrade to ${entry.versions.patched.join(" or ")}` : "no patched version published",
      ids: [advisory.id ? `https://rustsec.org/advisories/${advisory.id}` : null].filter(Boolean),
      title: advisory.title || null
    });
  }

  const warnings = payload?.warnings || {};
  for (const [kind, entries] of Object.entries(warnings)) {
    for (const entry of entries || []) {
      const advisory = entry.advisory || {};
      found.push({
        package: entry.package?.name || "unknown",
        version: entry.package?.version,
        severity: "low",
        fix: entry.versions?.patched?.length ? `upgrade to ${entry.versions.patched.join(" or ")}` : "no replacement published",
        ids: [advisory.id ? `https://rustsec.org/advisories/${advisory.id}` : null].filter(Boolean),
        title: advisory.title ? `${kind}: ${advisory.title}` : kind
      });
    }
  }
  return found;
}

/**
 * Which auditor to run for a project, and how to read it. Node picks the tool matching
 * the lockfile: running `npm audit` in a pnpm workspace reads a lockfile npm did not
 * write and reports on a tree that is not the installed one.
 */
async function auditorFor(project) {
  if (project.kind === "node") {
    if (await exists(path.join(project.directory, "pnpm-lock.yaml"))) {
      return { command: "pnpm", args: ["audit", "--json"], parse: fromNpm, label: "pnpm audit" };
    }
    if (await exists(path.join(project.directory, "yarn.lock"))) {
      return { command: "yarn", args: ["npm", "audit", "--json", "--all"], parse: fromNpm, label: "yarn npm audit" };
    }
    return { command: "npm", args: ["audit", "--json"], parse: fromNpm, label: "npm audit" };
  }
  if (project.kind === "dotnet" || project.kind === "csharp") {
    return {
      command: "dotnet",
      args: ["list", "package", "--vulnerable", "--include-transitive", "--format", "json"],
      parse: fromDotnet,
      label: "dotnet list package --vulnerable",
      // Without a restore there is no assets file and the command reports nothing useful.
      requires: async (directory) => (await exists(path.join(directory, "obj", "project.assets.json")))
        ? null
        : "the project has not been restored (run `dotnet restore` first)"
    };
  }
  if (project.kind === "python") {
    return { command: "pip-audit", args: ["--format", "json", "--progress-spinner", "off"], parse: fromPipAudit, label: "pip-audit" };
  }
  if (project.kind === "go") {
    return {
      command: "govulncheck",
      args: ["-json", "./..."],
      // Concatenated JSON objects, not one document.
      stream: true,
      parse: fromGovulncheck,
      label: "govulncheck",
      install: "go install golang.org/x/vuln/cmd/govulncheck@latest"
    };
  }
  if (project.kind === "rust") {
    return {
      command: "cargo",
      args: ["audit", "--json"],
      parse: fromCargoAudit,
      label: "cargo audit",
      install: "cargo install cargo-audit",
      // cargo-audit reads Cargo.lock; without one it fails with an unrelated-looking error.
      requires: async (directory) => (await exists(path.join(directory, "Cargo.lock")))
        ? null
        : "no Cargo.lock (run `cargo generate-lockfile` first)"
    };
  }
  return null;
}

/**
 * Audit one project. Never throws: a missing tool, an unrestored project, or an
 * unparsable payload degrades to a reported reason, because the deterministic scan is
 * the product and this is an addition to it.
 */
export async function auditProject(project, { root, limit = 60 }) {
  const auditor = await auditorFor(project);
  if (!auditor) {
    return { ran: false, reason: `no auditor for ${project.kind} projects`, findings: [] };
  }
  if (auditor.requires) {
    const blocker = await auditor.requires(project.directory);
    if (blocker) return { ran: false, tool: auditor.label, reason: blocker, findings: [] };
  }

  const result = await run(auditor.command, auditor.args, project.directory);
  if (!result.ok) {
    // A missing auditor is the common case for tools installed separately from the
    // toolchain, so say how to get it rather than only that it is absent.
    const reason = auditor.install && /not installed/.test(result.reason)
      ? `${result.reason} — install it with: ${auditor.install}`
      : result.reason;
    return { ran: false, tool: auditor.label, reason, findings: [] };
  }

  const payload = auditor.stream ? parseJsonStream(result.stdout) : parseJson(result.stdout);
  const empty = auditor.stream ? !payload.length : !payload;
  if (empty) {
    const detail = (result.stderr || "").split("\n").find(Boolean) || "no parsable output";
    // `cargo audit` on a clean tree and `govulncheck` with nothing to say both exit 0
    // with little output; that is a successful run reporting zero, not a failure.
    if (result.code === 0) return { ran: true, tool: auditor.label, total: 0, truncated: 0, findings: [] };
    // A subcommand-style auditor (`cargo audit`) is reached through a binary that does
    // exist, so the missing-tool branch above never fires — the failure arrives as a
    // "no such command" on stderr instead, and deserves the same install hint.
    const missingSubcommand = auditor.install && /no such command|unknown command|is not a .* command|not found/i.test(detail);
    return {
      ran: false,
      tool: auditor.label,
      reason: missingSubcommand ? `${auditor.label} is not installed — install it with: ${auditor.install}` : detail.slice(0, 160),
      findings: []
    };
  }

  let vulnerabilities;
  try {
    vulnerabilities = auditor.parse(payload);
  } catch (error) {
    return { ran: false, tool: auditor.label, reason: `could not read ${auditor.label} output: ${error.message}`, findings: [] };
  }

  const manifest = project.manifest || "package.json";
  const findings = vulnerabilities
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.package.localeCompare(b.package))
    .slice(0, limit)
    .map((entry) => ({
      file: manifest,
      line: 1,
      severity: entry.severity,
      evidence: `${entry.package}${entry.version ? `@${entry.version}` : entry.range ? ` ${entry.range}` : ""}`,
      message: [
        `\`${entry.package}\` has a ${entry.severity} advisory`,
        entry.transitive ? " (transitive)" : "",
        entry.title ? `: ${entry.title}` : "",
        `. ${entry.fix}.`,
        entry.ids.length ? ` See ${entry.ids[0]}.` : ""
      ].join(""),
      confidence: "high"
    }));

  return {
    ran: true,
    tool: auditor.label,
    total: vulnerabilities.length,
    truncated: Math.max(0, vulnerabilities.length - findings.length),
    findings
  };
}

function rank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

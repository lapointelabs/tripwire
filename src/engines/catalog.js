import path from "node:path";
import { findingsFromSarif } from "./sarif.js";

/**
 * The engines Tripwire delegates to.
 *
 * The premise: for commodity depth — an advisory database, 800 secret detectors, a
 * cross-file dataflow engine — a generalist scanner reimplementing it badly is worse than
 * no coverage at all, because a shallow pass that reports nothing reads exactly like a
 * clean one. Tripwire's own rules stay where a general tool has no competitor: the agent
 * surface, prompt-injection sinks, and the ways a repository lies to the model reading it.
 * Everything else is someone else's job, run through one config and normalized into one
 * finding model with one confidence scale, one score, and one fix plan.
 *
 * Rules every engine here obeys:
 *
 *   - **Opt-in.** Nothing spawns a subprocess or touches the network unless asked.
 *   - **Never bundled.** Tripwire does not vendor, download, or auto-install a binary.
 *     You install the engine; Tripwire finds it and reads its output.
 *   - **Bring your own key.** Commercial engines authenticate with your credentials from
 *     your environment. Tripwire reads no key file, writes no key, and proxies nothing.
 *   - **Absence is reported.** An engine that is not installed is named in the report
 *     along with what went unchecked, because a quiet report and a clean repository must
 *     never look the same.
 *
 * Each descriptor:
 *   launchers   how to invoke it, in preference order — the first installed one wins
 *   scope       "project" for per-project trees, "root" for repository-wide config
 *   attempts    argument sets tried in order, so a CLI rename between major versions
 *               degrades to a fallback rather than to a broken integration
 *   parse       payload -> engine findings (normalized in ./index.js)
 */

/** Bounded per engine so one noisy tool cannot dominate the report or the score. */
const DEFAULT_LIMIT = 120;

function severityFromCvss(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

const NAMED_SEVERITY = {
  critical: "critical", high: "high", moderate: "medium", medium: "medium",
  low: "low", info: "low", informational: "low", unknown: "medium"
};

/* ------------------------------------------------------------------ code analysis --- */

/**
 * Semgrep, or Opengrep — the LGPL fork kept when Semgrep's rules moved to a source-
 * available license. They share a CLI, so one adapter drives both; Opengrep is tried first
 * because it is the one that stays freely usable in a commercial CI pipeline.
 *
 * This is the engine that most directly fills a gap Tripwire states in its own limits:
 * Tripwire does no interprocedural dataflow, and a tainted value laundered through three
 * helpers in three files is invisible to it. Semgrep's dataflow — and, with a token, the
 * cross-file analysis in their Pro engine — sees it.
 */
const semgrep = {
  id: "semgrep",
  label: "Semgrep / Opengrep",
  domain: "code",
  covers: "deep pattern and dataflow SAST across 30+ languages",
  fills: "interprocedural dataflow — the gap Tripwire's own limits section names",
  homepage: "https://opengrep.dev",
  launchers: [{ command: "opengrep" }, { command: "semgrep" }],
  install: "brew install opengrep, or pipx install semgrep",
  scope: "project",
  network: true,
  networkReason: "fetches the rule pack from the registry unless a local ruleset is configured",
  byok: {
    env: ["SEMGREP_APP_TOKEN"],
    required: false,
    unlocks: "Semgrep Pro rules and cross-file (interfile) dataflow"
  },
  timeoutMs: 600_000,
  defaults: { config: "p/security-audit" },
  attempts({ dir, options }) {
    const config = options.config || semgrep.defaults.config;
    // `--metrics` is a subcommand option, not a global one. Ahead of `scan` it exits 2 —
    // after printing an empty but perfectly well-formed SARIF envelope, which is why the
    // runner treats a non-clean exit with zero findings as a failed attempt.
    const base = ["scan", "--sarif", "--quiet", "--config", String(config), dir];
    return [
      { args: ["scan", "--metrics=off", ...base.slice(1)], format: "json" },
      // Opengrep has no telemetry to disable and older builds reject the flag outright.
      { args: base, format: "json" }
    ];
  },
  parse(payload, context) {
    return findingsFromSarif(payload, {
      toRelative: context.toRelative,
      engine: semgrep.id,
      defaultSeverity: "medium"
    });
  }
};

/**
 * Snyk Code. Commercial, so it is BYOK and never runs without a token you already have —
 * Tripwire will not prompt for one, store one, or route a scan through anything of ours.
 */
const snykCode = {
  id: "snyk-code",
  label: "Snyk Code",
  domain: "code",
  covers: "commercial SAST with interfile dataflow and curated rules",
  homepage: "https://snyk.io",
  launchers: [{ command: "snyk" }],
  install: "npm i -g snyk (then `snyk auth`)",
  scope: "project",
  network: true,
  networkReason: "analysis runs in Snyk's cloud",
  paid: true,
  byok: {
    env: ["SNYK_TOKEN"],
    required: true,
    unlocks: "the whole engine — Snyk Code will not run unauthenticated"
  },
  timeoutMs: 600_000,
  attempts({ dir }) {
    return [
      { args: ["code", "test", "--sarif", dir], format: "json" },
      { args: ["code", "test", "--json", dir], format: "json" }
    ];
  },
  // Exit 3 means "no supported projects here", which is a clean result, not a failure.
  cleanExitCodes: [0, 3],
  parse(payload, context) {
    if (!payload?.runs) return [];
    return findingsFromSarif(payload, {
      toRelative: context.toRelative,
      engine: snykCode.id,
      defaultSeverity: "medium"
    });
  }
};

/* ----------------------------------------------------------------------- secrets --- */

/**
 * TruffleHog. Tripwire ships fourteen vendor token shapes; TruffleHog ships hundreds and,
 * far more importantly, **verifies** them — it calls the provider to ask whether the
 * credential is live.
 *
 * That single bit changes the report more than any amount of extra regex coverage. A
 * verified credential is not a pattern match to be triaged, argued about, or weighed by
 * confidence; it is a live key in a file, and it is reported as critical with no hedging.
 * An unverified one stays a lead.
 */
const trufflehog = {
  id: "trufflehog",
  label: "TruffleHog",
  domain: "secrets",
  covers: "800+ credential detectors with live verification against the issuing provider",
  fills: "verification — Tripwire can see a token shape but never whether the key still works",
  homepage: "https://github.com/trufflesecurity/trufflehog",
  launchers: [{ command: "trufflehog" }],
  install: "brew install trufflehog",
  scope: "project",
  network: true,
  networkReason: "verification calls each credential's issuer; --offline downgrades to detection only",
  timeoutMs: 300_000,
  attempts({ dir, offline }) {
    const verification = offline ? ["--no-verification"] : [];
    const base = ["filesystem", dir, "--json", ...verification];
    return [
      { args: ["--no-update", ...base], format: "ndjson" },
      { args: base, format: "ndjson" }
    ];
  },
  parse(entries, context) {
    const findings = [];
    for (const entry of entries) {
      const meta = entry?.SourceMetadata?.Data?.Filesystem || entry?.SourceMetadata?.Data?.Git || {};
      const file = context.toRelative(meta.file || meta.link);
      if (!file) continue;

      const verified = entry.Verified === true;
      const detector = entry.DetectorName || entry.DetectorType || "credential";
      findings.push({
        engine: trufflehog.id,
        externalRuleId: `trufflehog/${String(detector).toLowerCase().replace(/\s+/g, "-")}`,
        file,
        // TruffleHog reports 0 when a decoder cannot attribute a line; a finding at line 0
        // renders as a broken link in every editor and CI annotation that reads it.
        line: Math.max(1, Number(meta.line) || 1),
        severity: verified ? "critical" : "high",
        // A verified credential is not an opinion. An unverified one is a strong lead:
        // the shape matched a real vendor format, but the key may be revoked or fake.
        confidence: verified ? "high" : "medium",
        verified,
        title: verified ? `Live ${detector} credential` : `${detector} credential`,
        message: verified
          ? `A **verified** ${detector} credential is committed here — TruffleHog authenticated with it successfully. Treat it as compromised: rotate it before removing the line.`
          : `A ${detector} credential shape is committed here. TruffleHog could not verify it${entry.VerificationError ? ` (${String(entry.VerificationError).slice(0, 80)})` : ""}, so it may be revoked, a placeholder, or live but unreachable from this network.`,
        // Never the raw value. Reporting a secret in a file that lands in CI logs and a
        // fix plan would leak it a second time.
        evidence: entry.Redacted ? String(entry.Redacted).slice(0, 80) : `${detector} (value withheld)`,
        refs: []
      });
    }
    return findings;
  }
};

/**
 * Gitleaks. Offline, fast, and MIT — the one to reach for on an air-gapped build agent
 * where TruffleHog's verification step is not just unavailable but actively unwanted.
 */
const gitleaks = {
  id: "gitleaks",
  label: "Gitleaks",
  domain: "secrets",
  covers: "fast offline secret detection with entropy scoring",
  homepage: "https://github.com/gitleaks/gitleaks",
  launchers: [{ command: "gitleaks" }],
  install: "brew install gitleaks",
  scope: "project",
  network: false,
  timeoutMs: 180_000,
  // Gitleaks writes its report to a path rather than stdout; the runner supplies a
  // temporary file outside the repository and reads it back.
  reportFile: ".json",
  attempts({ dir, reportPath }) {
    const base = ["--source", dir, "--no-git", "--redact", "--report-format", "json", "--report-path", reportPath, "--exit-code", "0"];
    return [
      { args: ["detect", ...base], format: "json" },
      { args: ["dir", dir, "--redact", "--report-format", "json", "--report-path", reportPath, "--exit-code", "0"], format: "json" }
    ];
  },
  parse(payload, context) {
    const entries = Array.isArray(payload) ? payload : [];
    const findings = [];
    for (const entry of entries) {
      const file = context.toRelative(entry.File);
      if (!file) continue;
      const line = Math.max(1, Number(entry.StartLine) || 1);
      findings.push({
        engine: gitleaks.id,
        externalRuleId: `gitleaks/${entry.RuleID || "generic"}`,
        file,
        line,
        endLine: Math.max(line, Number(entry.EndLine) || line),
        severity: "high",
        // No verification step, so this stays a lead however good the entropy score is.
        confidence: "medium",
        verified: false,
        title: entry.Description || "Committed credential",
        message: `${entry.Description || "A credential"} was detected here${entry.Entropy ? ` (entropy ${Number(entry.Entropy).toFixed(1)})` : ""}. Gitleaks does not verify credentials, so confirm whether the key is live, then rotate it before removing the line.`,
        evidence: entry.Match ? String(entry.Match).slice(0, 80) : "value withheld",
        refs: []
      });
    }
    return findings;
  }
};

/* ------------------------------------------------------------------ dependencies --- */

/**
 * osv-scanner. One binary, one database, every ecosystem — which is why it is preferred
 * over the per-ecosystem auditors behind `--audit`. Those stay as the fallback because
 * they need no install: `npm audit` and `dotnet list package` ship with the toolchain.
 */
const osvScanner = {
  id: "osv-scanner",
  label: "osv-scanner",
  domain: "deps",
  covers: "OSV advisories across every ecosystem from a single lockfile pass",
  homepage: "https://google.github.io/osv-scanner/",
  launchers: [{ command: "osv-scanner" }],
  install: "brew install osv-scanner",
  scope: "project",
  network: true,
  networkReason: "queries the OSV database; pass --offline to skip",
  timeoutMs: 300_000,
  attempts({ dir }) {
    return [
      // v2 moved the directory scan under `scan source`; v1 took it at the top level.
      { args: ["scan", "source", "--format", "json", "--recursive", dir], format: "json" },
      { args: ["scan", "--format", "json", "--recursive", dir], format: "json" },
      { args: ["--format", "json", "--recursive", dir], format: "json" }
    ];
  },
  cleanExitCodes: [0, 1],
  parse(payload, context) {
    const findings = [];
    for (const result of payload?.results || []) {
      const file = context.toRelative(result.source?.path) || context.manifest;
      for (const entry of result.packages || []) {
        const name = entry.package?.name || "unknown";
        const version = entry.package?.version;

        // `groups` carries the scanner's own computed max severity per advisory cluster;
        // the raw `severity` array holds CVSS vectors, not numbers.
        const maxByGroup = new Map();
        for (const group of entry.groups || []) {
          const severity = severityFromCvss(group.max_severity);
          for (const id of group.ids || []) maxByGroup.set(id, severity);
        }

        for (const vulnerability of entry.vulnerabilities || []) {
          const severity = maxByGroup.get(vulnerability.id)
            || NAMED_SEVERITY[String(vulnerability.database_specific?.severity || "").toLowerCase()]
            || "high";
          const alias = (vulnerability.aliases || []).find((value) => value.startsWith("CVE-"));
          findings.push({
            engine: osvScanner.id,
            externalRuleId: vulnerability.id,
            file,
            line: 1,
            severity,
            confidence: "high",
            title: "Dependency with a known vulnerability",
            message: `\`${name}${version ? `@${version}` : ""}\` is affected by ${vulnerability.id}${alias ? ` (${alias})` : ""}${vulnerability.summary ? `: ${vulnerability.summary}` : ""}. See https://osv.dev/${vulnerability.id}.`,
            evidence: `${name}${version ? `@${version}` : ""}`,
            refs: [`https://osv.dev/${vulnerability.id}`]
          });
        }
      }
    }
    return findings;
  }
};

/* ----------------------------------------------------------------- agent surface --- */

/**
 * Snyk Agent Scan. The one engine here that looks at the surface Tripwire was built for
 * and still cannot reach: the MCP servers and skills an agent actually loads. Tripwire
 * reads the repository's instruction files; this reads the tools those instructions hand
 * the model, and checks their descriptions for injection and exfiltration payloads.
 *
 * Tripwire passes explicit config paths from this repository rather than letting it sweep
 * the machine, and **never** passes `--dangerously-run-mcp-servers`. That flag executes
 * every command in an MCP config — which is the correct way to inspect a server's live
 * tool list, and an unacceptable thing for a security scanner to do to you by default.
 */
const agentScan = {
  id: "snyk-agent-scan",
  label: "Snyk Agent Scan",
  domain: "agent-surface",
  covers: "MCP server and skill inspection for prompt injection and hidden payloads",
  fills: "the tools an agent loads — Tripwire reads instruction files, not the MCP surface",
  homepage: "https://github.com/snyk/agent-scan",
  launchers: [
    { command: "snyk-agent-scan" },
    // Shipped on PyPI; uvx runs it without a permanent install.
    { command: "uvx", prefix: ["snyk-agent-scan@latest"] }
  ],
  install: "uv tool install snyk-agent-scan, or pipx install snyk-agent-scan",
  scope: "root",
  network: true,
  networkReason: "resolves the package and its threat rules",
  timeoutMs: 300_000,
  /**
   * Only when this repository declares MCP servers. Run with no path argument the tool
   * sweeps the whole machine — every agent config in the home directory — which is a
   * legitimate thing to want and an indefensible thing to do to someone who typed
   * `tripwire scan` in a project folder.
   */
  appliesTo({ mcpConfigs }) {
    return mcpConfigs.length ? null : "no MCP server configuration in this repository";
  },
  attempts({ mcpConfigs }) {
    // Static analysis only. `--dangerously-run-mcp-servers` would execute every command in
    // these configs, and a scanner that does that without being asked is a supply-chain
    // risk wearing a security tool's name.
    return [{ args: [...mcpConfigs, "--json"], format: "json" }];
  },
  cleanExitCodes: [0, 1],
  parse(payload, context) {
    const findings = [];
    if (!payload || typeof payload !== "object") return findings;

    // The documented root is a map of scan path to a result object holding `issues`, but
    // the nested shape is only partly specified and has moved between releases. Collecting
    // issue arrays wherever they appear survives that; a missing severity is treated as
    // the more serious option rather than the less.
    const walk = (node, scanPath) => {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) {
        for (const item of node) walk(item, scanPath);
        return;
      }
      for (const issue of node.issues || []) {
        if (!issue?.code) continue;
        // `E###` is an error-tier security finding, `W###` a warning, `X###` a runtime
        // failure of the scanner itself rather than a finding about your repository.
        const tier = String(issue.code)[0].toUpperCase();
        if (tier === "X") continue;
        findings.push({
          engine: agentScan.id,
          externalRuleId: `snyk-agent-scan/${issue.code}`,
          file: context.toRelative(scanPath) || scanPath,
          line: 1,
          severity: tier === "E" ? "critical" : "medium",
          confidence: tier === "E" ? "high" : "medium",
          title: tier === "E" ? "Malicious or unsafe agent component" : "Agent component warning",
          message: `${issue.message || issue.code} (${issue.code}). This is the MCP/skill surface your agent loads, not repository source — a payload here reaches the model on every session.`,
          evidence: issue.code,
          refs: []
        });
      }
      for (const [key, value] of Object.entries(node)) {
        if (key === "issues") continue;
        walk(value, scanPath);
      }
    };

    for (const [scanPath, result] of Object.entries(payload)) walk(result, scanPath);
    return findings;
  }
};

/**
 * agnix. A linter for the instruction files themselves — CLAUDE.md, AGENTS.md, SKILL.md,
 * hooks, MCP config — across ten harnesses and several hundred rules.
 *
 * This is the engine that overlaps Tripwire most, and the overlap is deliberate: agnix
 * covers correctness and convention at breadth Tripwire will not match, while Tripwire's
 * context rules ask whether the file is *true* — whether the script it names still exists,
 * whether the doc block agrees with the signature. Findings from both are deduplicated by
 * file and line before they reach the report.
 */
const agnix = {
  id: "agnix",
  label: "agnix",
  domain: "agent-config",
  covers: "440+ rules validating CLAUDE.md, AGENTS.md, SKILL.md, hooks and MCP config",
  homepage: "https://github.com/agent-sh/agnix",
  launchers: [{ command: "agnix" }],
  install: "cargo install agnix-cli",
  scope: "root",
  network: false,
  timeoutMs: 120_000,
  appliesTo({ agentFiles, mcpConfigs, skills }) {
    return (agentFiles.length || mcpConfigs.length || skills.length)
      ? null
      : "no agent instruction files in this repository";
  },
  attempts({ dir }) {
    return [{ args: ["--format", "sarif", dir], format: "json" }];
  },
  cleanExitCodes: [0, 1, 2],
  parse(payload, context) {
    return findingsFromSarif(payload, {
      toRelative: context.toRelative,
      engine: agnix.id,
      // agnix reports a great deal of convention and style alongside the security rules;
      // anything it does not explicitly raise stays low so it cannot swamp the score.
      defaultSeverity: "low"
    });
  }
};

export const ENGINES = [semgrep, snykCode, trufflehog, gitleaks, osvScanner, agentScan, agnix];

export const DOMAINS = {
  code: { label: "Code analysis", native: "injection, web, and taint rules" },
  secrets: { label: "Secrets", native: "14 vendor token formats, no verification" },
  deps: { label: "Dependencies", native: "supply-chain posture only, no advisory database" },
  "agent-surface": { label: "Agent surface", native: "none — Tripwire does not inspect MCP servers or skills" },
  "agent-config": { label: "Agent instructions", native: "stale references, contradictions, injection phrasing" }
};

export function engineById(id) {
  return ENGINES.find((engine) => engine.id === id) || null;
}

export { DEFAULT_LIMIT };

/** Where an engine's report file goes, if it insists on writing one. */
export function reportFileName(engine, suffix) {
  return path.join(`tripwire-${engine.id}${suffix}`);
}

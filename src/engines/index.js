import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { firstLine, parseJson, parseNdjson, runTool, toolExists } from "../exec.js";
import { ruleForDomain } from "../rules/external.js";
import { DEFAULT_LIMIT, DOMAINS, ENGINES, engineById } from "./catalog.js";
import { toPosix } from "../util.js";

export { DOMAINS, ENGINES, engineById };

/**
 * Running the external engines and folding their results into one report.
 *
 * The value Tripwire adds over running these tools by hand is not that it types the
 * commands for you. It is that afterwards there is one finding model, one confidence
 * scale, one score, one deduplicated list, and one fix plan — and a stated account of
 * which engines did not run and what therefore went unchecked.
 */

/** Engines run one at a time. Several are CPU-bound and all of them are somebody's laptop. */
async function resolveLauncher(engine) {
  for (const launcher of engine.launchers) {
    if (await toolExists(launcher.command)) return launcher;
  }
  return null;
}

/**
 * Decide, per engine, whether it can run — and if not, exactly why.
 *
 * The reason strings are the product here as much as the findings are. "Not installed"
 * with the install command beats a silent omission, and "installed but SNYK_TOKEN is not
 * set" beats "not installed" when the binary is right there.
 */
export async function planEngines(context) {
  const plan = [];
  for (const engine of ENGINES) {
    const options = context.config[engine.id] || {};
    const selected = context.selection === "all"
      || (Array.isArray(context.selection) && context.selection.includes(engine.id))
      || (context.selection === "auto" && options.enabled !== false);

    if (!selected) {
      plan.push({ engine, run: false, status: "not-selected", reason: "not selected" });
      continue;
    }
    if (options.enabled === false) {
      plan.push({ engine, run: false, status: "disabled", reason: "disabled in tripwire.config.json" });
      continue;
    }

    const blocker = engine.appliesTo ? engine.appliesTo(context) : null;
    if (blocker) {
      plan.push({ engine, run: false, status: "not-applicable", reason: blocker });
      continue;
    }

    const configuredNetworkArg = engine.networkArgs?.find((arg) => options.args?.includes(arg));
    if (context.offline && (engine.network || configuredNetworkArg)) {
      const reason = engine.network
        ? engine.networkReason
        : `configured argument ${configuredNetworkArg} enables a network analyzer`;
      plan.push({ engine, run: false, status: "offline", reason: `needs the network (${reason}) and --offline was passed` });
      continue;
    }

    const launcher = await resolveLauncher(engine);
    if (!launcher) {
      plan.push({
        engine,
        run: false,
        status: "missing",
        // In auto mode a missing engine is expected, not an error — say what it would have
        // covered and how to get it, then move on.
        reason: `not installed — install with: ${engine.install}`
      });
      continue;
    }

    const keys = engine.byok?.env || [];
    const key = keys.find((name) => process.env[name]);
    if (engine.byok?.required && !key) {
      plan.push({
        engine,
        run: false,
        status: "no-key",
        launcher,
        reason: `installed, but no key — set ${keys.join(" or ")} (${engine.byok.unlocks})`
      });
      continue;
    }

    plan.push({ engine, run: true, launcher, key, options, status: "ready" });
  }
  return plan;
}

/** Run one engine, trying each argument set until one produces something parsable. */
export async function runEngine(entry, context) {
  const { engine, launcher, options = {} } = entry;
  const dir = engine.scope === "root" ? context.root : context.projectDir;

  let workspace = null;
  let reportPath = null;
  if (engine.reportFile) {
    // Outside the repository, always: a scanner that drops a report into the tree it is
    // scanning makes that report input to its own next run.
    workspace = await mkdtemp(path.join(tmpdir(), "tripwire-"));
    reportPath = path.join(workspace, `${engine.id}${engine.reportFile}`);
  }

  try {
    const attempts = engine.attempts({
      dir,
      root: context.root,
      project: context.project,
      options,
      offline: context.offline,
      reportPath,
      agentFiles: context.agentFiles,
      mcpConfigs: context.mcpConfigs,
      skills: context.skills
    });

    const failures = [];
    for (const attempt of attempts) {
      const result = await runTool({
        command: launcher.command,
        args: [...(launcher.prefix || []), ...attempt.args, ...(options.args || [])],
        cwd: context.projectDir,
        timeoutMs: options.timeoutMs || engine.timeoutMs,
        env: options.env
      });

      if (!result.ok) {
        failures.push(result.reason);
        // A timeout is a property of this repository, not of the argument set. Trying the
        // next one just spends the timeout again.
        if (result.timedOut) break;
        continue;
      }

      const clean = (engine.cleanExitCodes || [0]).includes(result.code);
      const raw = reportPath ? await readReport(reportPath) : result.stdout;
      const payload = attempt.format === "ndjson" ? parseNdjson(raw) : parseJson(raw);
      const unparsable = attempt.format === "ndjson" ? !payload.length : payload === null;

      if (unparsable) {
        // Nothing to report and a clean exit is a successful run finding zero — which is
        // a different fact from a run that failed, and must not be reported as the same.
        if (clean) return { ran: true, tool: label(engine, launcher), findings: [], total: 0 };
        failures.push(firstLine(result.stderr) || `exited ${result.code} with no parsable output`);
        continue;
      }

      let findings;
      try {
        findings = engine.parse(payload, context) || [];
      } catch (error) {
        failures.push(`could not read ${engine.label} output: ${error.message}`);
        continue;
      }

      /**
       * A well-formed envelope is not proof the tool ran.
       *
       * Semgrep, given a flag in the wrong position, exits 2 and prints a complete,
       * schema-valid SARIF document containing zero results. Parsed alone that is
       * indistinguishable from a clean scan, and reporting it as one is the worst failure
       * this layer has: a green result that means "the command was malformed".
       *
       * So a non-clean exit only counts when the tool actually produced findings —
       * scanners do exit non-zero *because* they found something, and that case is real.
       * Otherwise the attempt failed and the next argument set gets a turn.
       */
      if (!clean && !findings.length) {
        failures.push(firstLine(result.stderr) || `exited ${result.code} reporting nothing`);
        continue;
      }

      return { ran: true, tool: label(engine, launcher), findings, total: findings.length };
    }

    return { ran: false, tool: label(engine, launcher), reason: failures[0] || "produced no usable output", findings: [] };
  } finally {
    if (workspace) await rm(workspace, { recursive: true, force: true }).catch(() => {});
  }
}

function label(engine, launcher) {
  // Name the binary that actually ran. "Semgrep / Opengrep" in a report is useless when
  // the question is which of the two produced a finding you disagree with.
  return launcher.prefix?.length ? `${launcher.command} ${launcher.prefix[0]}` : launcher.command;
}

async function readReport(reportPath) {
  try {
    return await readFile(reportPath, "utf8");
  } catch {
    return "";
  }
}

/**
 * Run every planned engine and return normalized Tripwire findings plus a coverage record.
 *
 * Never throws. An engine layer that can take down the deterministic scan is a worse
 * product than no engine layer, because the deterministic scan is the part that always
 * works.
 */
export async function runEngines(context) {
  const plan = await planEngines(context);
  const coverage = [];
  const findings = [];

  for (const entry of plan) {
    if (!entry.run) {
      coverage.push({
        id: entry.engine.id,
        label: entry.engine.label,
        domain: entry.engine.domain,
        covers: entry.engine.covers,
        ran: false,
        status: entry.status,
        reason: entry.reason
      });
      continue;
    }

    context.onProgress?.({ kind: "engine", engine: entry.engine.id });

    let outcome;
    try {
      outcome = await runEngine(entry, context);
    } catch (error) {
      outcome = { ran: false, reason: error.message, findings: [] };
    }

    const limit = entry.options?.limit || DEFAULT_LIMIT;
    const kept = outcome.findings.slice(0, limit);
    for (const finding of kept) findings.push(toFinding(finding, entry.engine));

    coverage.push({
      id: entry.engine.id,
      label: entry.engine.label,
      domain: entry.engine.domain,
      covers: entry.engine.covers,
      ran: outcome.ran,
      status: outcome.ran ? "ran" : "failed",
      tool: outcome.tool,
      total: outcome.total ?? 0,
      // Say what was dropped. A cap that silently truncates reads as full coverage.
      truncated: Math.max(0, (outcome.findings?.length || 0) - kept.length),
      usedKey: Boolean(entry.key),
      keyName: entry.key || null,
      reason: outcome.reason || null
    });
  }

  return { coverage, findings };
}

/**
 * Map an engine finding onto the shape the rest of Tripwire already handles.
 *
 * The two decisions that matter here are confidence and whether to triage. Secrets are
 * never sent to a model — the file holds a credential, and sending it for review would
 * leak it to a third party in the course of reporting that it leaked. Advisories are never
 * sent either: the ecosystem already answered that question authoritatively. Everything
 * else follows the normal rule, where uncertainty is what buys a second opinion.
 */
export function toFinding(item, engine) {
  const domain = item.domain || engine.domain;
  const rule = ruleForDomain(domain);
  const confidence = item.confidence || "medium";
  const triageable = domain !== "secrets" && domain !== "deps" && confidence !== "high";

  return {
    id: `${rule.id}:${engine.id}:${item.file}:${item.line}:${item.externalRuleId}`,
    ruleId: rule.id,
    category: rule.category,
    severity: item.severity || rule.severity,
    // The Tripwire rule title, not the engine's — findings are grouped by rule id, and a
    // group whose heading is whichever finding happened to sort first mislabels the rest.
    // The engine's specific title leads the message instead, where it belongs to one site.
    title: rule.title,
    why: rule.why,
    fix: rule.fix,
    file: item.file,
    line: item.line,
    endLine: item.endLine || item.line,
    evidence: item.evidence || "",
    message: item.title && item.message && !item.message.startsWith(item.title)
      ? `**${item.title}.** ${item.message}`
      : item.message || item.title || rule.title,
    confidence,
    aiTriage: triageable,
    verdict: null,
    // Provenance, carried all the way into findings.json, SARIF, and the fix plan. A
    // finding whose origin cannot be traced back to the engine and rule that raised it is
    // a finding nobody can argue with, and arguing with findings is how triage works.
    source: {
      engine: engine.id,
      label: engine.label,
      ruleId: item.externalRuleId,
      domain,
      verified: item.verified,
      refs: item.refs || []
    }
  };
}

/**
 * Which broad question a finding answers, so overlapping engines can be reconciled.
 *
 * Two tools reporting the same credential on the same line is the most likely outcome of
 * turning several on at once, and a report that lists it twice is worse than either tool
 * alone — it is the exact "wired-together" failure the engine layer exists to avoid.
 */
function domainOf(finding) {
  if (finding.source) return finding.source.domain || engineById(finding.source.engine)?.domain || "code";
  const { ruleId } = finding;
  if (ruleId.startsWith("secrets/") || ruleId === "context/secret-in-agent-context") return "secrets";
  if (ruleId === "supply-chain/vulnerable-dependency") return "deps";
  if (ruleId.startsWith("context/") || ruleId.startsWith("llm/")) return "agent-config";
  if (ruleId.startsWith("injection/") || ruleId.startsWith("web/") || ruleId.startsWith("taint/")) return "code";
  return ruleId.split("/")[0];
}

/**
 * How much a source's word is worth when two of them describe the same thing.
 *
 * A verified credential outranks everything: the engine authenticated with the key. A
 * published advisory outranks a pattern match. Tripwire's own high-confidence rules
 * outrank an external engine's uncertain ones, because a native finding carries rule text
 * written for this report and an `explain` entry listing its known false positives.
 */
function authority(finding) {
  if (finding.source?.verified === true) return 0;
  if (domainOf(finding) === "deps") return 1;
  if (!finding.source && finding.confidence === "high") return 2;
  if (finding.confidence === "high") return 3;
  if (!finding.source) return 4;
  return 5;
}

/** Secrets tools disagree by a line or two about where a multi-line credential starts. */
const LINE_TOLERANCE = { secrets: 2, deps: Infinity };

/**
 * Collapse findings that different sources raised about the same thing.
 *
 * The survivor is the most authoritative one, and it records who else agreed — corroboration
 * is information. Two independent engines flagging the same line is a stronger signal than
 * either alone, and a developer deciding whether to spend an afternoon on a finding should
 * be told that both Semgrep and Tripwire think it is real.
 */
export function reconcile(findings) {
  const buckets = new Map();
  for (const finding of findings) {
    const domain = domainOf(finding);
    const tolerance = LINE_TOLERANCE[domain] ?? 0;
    // For deps the line number is meaningless (everything points at the manifest), so the
    // package name in the evidence is the identity instead.
    const anchor = tolerance === Infinity
      ? finding.evidence
      : String(Math.floor(finding.line / (tolerance * 2 + 1)));
    const key = `${domain}:${finding.file}:${anchor}`;
    const list = buckets.get(key);
    if (list) list.push(finding);
    else buckets.set(key, [finding]);
  }

  const result = [];
  for (const group of buckets.values()) {
    if (group.length === 1) {
      result.push(group[0]);
      continue;
    }
    // Line bucketing can merge neighbours that are genuinely different findings, so
    // require the external rule identity to differ before treating them as duplicates of
    // one another rather than as separate problems.
    const sorted = [...group].sort((a, b) => authority(a) - authority(b) || a.line - b.line);
    const winner = { ...sorted[0] };
    const others = sorted.slice(1);

    winner.corroboratedBy = [...new Set(others.map((finding) => finding.source?.label || "Tripwire"))]
      .filter((name) => name !== (winner.source?.label || "Tripwire"));
    winner.duplicatesSuppressed = others.length;

    // Agreement across independent engines is evidence. It cannot manufacture certainty
    // out of two guesses, so it lifts low to medium and stops there.
    if (winner.corroboratedBy.length && winner.confidence === "low") winner.confidence = "medium";

    result.push(winner);
  }
  return result;
}

/**
 * Which domains nobody covered, phrased as what was not checked.
 *
 * This is the engine layer's version of the gated-rules line: the point of turning five
 * tools into one is that the one can tell you which of the five is missing.
 */
export function uncoveredDomains(coverage) {
  const covered = new Set(coverage.filter((entry) => entry.ran).map((entry) => entry.domain));
  return Object.entries(DOMAINS)
    .filter(([domain]) => !covered.has(domain))
    .map(([domain, detail]) => ({ domain, ...detail }));
}

/** Repository-relative POSIX path, or null when the engine reported something outside it. */
export function relativizer(root) {
  const resolvedRoot = path.resolve(root);
  return (value) => {
    if (!value) return null;
    let candidate = String(value);
    if (candidate.startsWith("file://")) {
      try {
        candidate = decodeURIComponent(new URL(candidate).pathname);
      } catch {
        return null;
      }
    }
    const absolute = path.isAbsolute(candidate) ? candidate : path.resolve(resolvedRoot, candidate);
    const relative = path.relative(resolvedRoot, absolute);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return null;
    return toPosix(relative);
  };
}

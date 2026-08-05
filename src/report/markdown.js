import { CATEGORIES } from "../rules/index.js";
import { activeFindings, groupByRule } from "../score.js";
import { pluralize } from "../util.js";

/** The human-facing report: what was found, how sure we are, and what was not checked. */
export function renderReportMarkdown(result, meta) {
  const { summary, project, stats, gatedRules, ai, capabilities } = result;
  const active = activeFindings(result.findings);
  const groups = groupByRule(active);
  const out = [];

  out.push(`# Tripwire report — ${escapeText(project.name)}`);
  out.push("");
  out.push(`**${summary.score}/100 · ${summary.grade}** — ${active.length} ${pluralize(active.length, "finding")} across ${stats.files} ${pluralize(stats.files, "file")} (${stats.lines.toLocaleString()} lines).`);
  out.push("");
  out.push(`| | |`);
  out.push(`| --- | --- |`);
  out.push(`| Project | ${inlineCode(project.relative)} |`);
  out.push(`| Stack | ${escapeCell(`${project.language} · ${project.framework}`)} |`);
  out.push(`| Scanned | ${escapeCell(meta.scannedAt)} |`);
  out.push(`| Tripwire | ${escapeCell(meta.version)} |`);
  out.push(`| Triage | ${escapeCell(ai?.used ? `${ai.label} · ${ai.model}` : "none — pattern confidence only")} |`);
  if (result.baseline) out.push(`| Baseline | ${result.baseline.new} new · ${result.baseline.unchanged} known · ${result.baseline.resolved} resolved |`);
  out.push("");

  out.push(`## Severity`);
  out.push("");
  out.push(`| Severity | Count |`);
  out.push(`| --- | ---: |`);
  for (const [severity, count] of Object.entries(summary.bySeverity)) {
    out.push(`| ${severity[0].toUpperCase()}${severity.slice(1)} | ${count} |`);
  }
  out.push("");

  if (Object.keys(summary.byCategory).length) {
    out.push(`## Categories`);
    out.push("");
    out.push(`| Category | Count |`);
    out.push(`| --- | ---: |`);
    for (const [category, count] of Object.entries(summary.byCategory).sort((a, b) => b[1] - a[1])) {
      out.push(`| ${CATEGORIES[category]?.label || category} | ${count} |`);
    }
    out.push("");
  }

  if (result.engines) {
    out.push(`## Engines`);
    out.push("");
    out.push(`| Engine | Covers | Status |`);
    out.push(`| --- | --- | --- |`);
    for (const entry of result.engines.coverage) {
      const status = entry.ran
        ? `ran as \`${entry.tool}\` — ${entry.total} ${pluralize(entry.total, "finding")}${entry.usedKey ? ` (authenticated with \`${entry.keyName}\`)` : ""}`
        : entry.reason;
      out.push(`| ${escapeCell(entry.label)} | ${escapeCell(entry.covers)} | ${escapeCell(status)} |`);
    }
    out.push("");
    if (result.engines.deduplicated) {
      const count = result.engines.deduplicated;
      out.push(`${count} ${pluralize(count, "finding")} ${pluralize(count, "was", "were")} reported by more than one source and collapsed into one, keeping the most authoritative version and noting who else agreed.`);
      out.push("");
    }
  }

  out.push(`## What this scan did not cover`);
  out.push("");
  out.push(readCoverage(capabilities, gatedRules, ai, result.audit, result.engines));
  out.push("");

  if (!groups.length) {
    out.push(`## Findings`);
    out.push("");
    out.push("None. Every active rule ran clean against this project.");
    out.push("");
    return `${out.join("\n")}\n`;
  }

  out.push(`## Findings`);
  out.push("");
  for (const group of groups) {
    out.push(`### ${severityBadge(group.severity)} ${escapeText(group.title)}${group.findings.length > 1 ? ` (${group.findings.length})` : ""}`);
    out.push("");
    out.push(`${inlineCode(group.ruleId)} · ${escapeText(CATEGORIES[group.category]?.label || group.category)}`);
    out.push("");
    out.push(`**Why this matters.** ${escapeText(group.why)}`);
    out.push("");
    out.push(`**How to fix it.** ${escapeText(group.fix)}`);
    out.push("");
    out.push(`| Location | Evidence | Confidence |`);
    out.push(`| --- | --- | --- |`);
    for (const finding of group.findings) {
      out.push(`| ${inlineCode(`${finding.file}:${finding.line}`)} | ${escapeCell(finding.evidence || finding.message)} | ${escapeCell(confidenceLabel(finding))} |`);
    }
    out.push("");
    const verified = group.findings.filter((finding) => finding.verdict?.reason);
    if (verified.length) {
      out.push(`<details><summary>Triage notes</summary>`);
      out.push("");
      for (const finding of verified) {
        out.push(`- ${inlineCode(`${finding.file}:${finding.line}`)} — ${escapeText(finding.verdict.reason)}`);
      }
      out.push("");
      out.push(`</details>`);
      out.push("");
    }
  }

  const refuted = result.findings.filter((finding) => finding.verdict?.real === false);
  if (refuted.length) {
    out.push(`## Refuted during triage (${refuted.length})`);
    out.push("");
    out.push("These matched a rule but the review model found the surrounding code already handles the concern. They are excluded from the score. Spot-check a few — a refutation is a judgment, not a proof.");
    out.push("");
    for (const finding of refuted) {
      out.push(`- ${inlineCode(`${finding.file}:${finding.line}`)} — ${inlineCode(finding.ruleId)}: ${escapeText(finding.verdict.reason)}`);
    }
    out.push("");
  }

  return `${out.join("\n")}\n`;
}

function readCoverage(capabilities, gatedRules, ai, audit, engines) {
  const notes = [];
  if (!engines) {
    notes.push(`- **No external engines ran.** Tripwire's own rules are a broad first pass; deeper coverage — cross-file dataflow, credential verification, MCP and skill inspection — is delegated to engines you install. Re-run with \`--engines\`, or run \`tripwire engines\` to see what is available.`);
  } else {
    for (const gap of engines.uncovered || []) {
      notes.push(`- **${escapeText(gap.label)} had no engine.** Tripwire's own coverage of this domain is ${escapeText(gap.native)}, and nothing deeper ran against it.`);
    }
    const notRun = new Set(["failed", "no-key", "offline", "disabled"]);
    for (const entry of engines.coverage.filter((item) => notRun.has(item.status))) {
      notes.push(`- **${escapeText(entry.label)} did not run:** ${escapeText(entry.reason)}. It would have covered ${escapeText(entry.covers)}.`);
    }
    if (engines.offline) {
      notes.push(`- **Offline mode was on.** Engines needing the network were skipped, and credential verification was disabled — a secret reported here was matched by shape, not confirmed against its issuer.`);
    }
  }
  if (audit?.ran) {
    notes.push(`- **${audit.tool} reported ${audit.total} vulnerable ${audit.total === 1 ? "dependency" : "dependencies"}.**${audit.truncated ? ` ${audit.truncated} beyond the reporting limit are not listed.` : ""}`);
  } else if (audit) {
    notes.push(`- **The dependency audit did not run:** ${audit.reason}. Known-vulnerable dependencies were not checked.`);
  } else {
    notes.push(`- **Dependency vulnerabilities were not checked.** Re-run with \`--audit\` to invoke the ecosystem auditor.`);
  }
  if (gatedRules.length) {
    const byReason = new Map();
    for (const rule of gatedRules) {
      if (!byReason.has(rule.reason)) byReason.set(rule.reason, []);
      byReason.get(rule.reason).push(rule.id);
    }
    for (const [reason, ids] of byReason) {
      notes.push(`- **${ids.length} ${reason} ${pluralize(ids.length, "rule")} did not run.** No ${reason} usage was detected in this project's manifest, so these were gated off rather than reported as clean: ${ids.map((id) => `\`${id}\``).join(", ")}.`);
    }
  }
  if (!ai?.used) {
    notes.push(`- **No model triage ran.** Low- and medium-confidence findings are unverified pattern matches. Some are real, some are not; the score weights them down but does not remove them.`);
  }
  if (ai?.truncated) {
    notes.push(`- **${ai.truncated} uncertain ${pluralize(ai.truncated, "finding")} exceeded the triage budget** and kept their pattern-match confidence.`);
  }
  notes.push(`- **Tripwire reads source text, not a running program.** It cannot see values that arrive at runtime, configuration applied by a deployment, or a framework's implicit protections. Absence of a finding is not proof of absence of a bug.`);
  if (!capabilities.ai) {
    notes.push(`- **The prompt-injection rules were gated off** because no model SDK appears in this project's dependencies.`);
  }
  return notes.join("\n");
}

function severityBadge(severity) {
  return { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪" }[severity] || "⚪";
}

function confidenceLabel(finding) {
  if (finding.verdict?.real === true) return `Confirmed (${finding.verdict.confidence})`;
  return { high: "High", medium: "Likely", low: "Unverified" }[finding.confidence] || finding.confidence;
}

function escapeCell(value) {
  return escapeText(value).replace(/\|/g, "\\|").slice(0, 140);
}

function escapeText(value) {
  return String(value ?? "")
    .replace(/[&<>]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[character])
    .replace(/\r?\n/g, " ");
}

function inlineCode(value) {
  const escaped = escapeText(value);
  const longest = Math.max(0, ...[...escaped.matchAll(/`+/g)].map((match) => match[0].length));
  const fence = "`".repeat(Math.max(1, longest + 1));
  const padding = escaped.startsWith("`") || escaped.endsWith("`") ? " " : "";
  return `${fence}${padding}${escaped}${padding}${fence}`;
}

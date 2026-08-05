import { CATEGORIES } from "../rules/index.js";
import { activeFindings, groupByRule } from "../score.js";
import { pluralize } from "../util.js";

const SEVERITY_STYLE = {
  critical: { icon: "▲", color: "red", label: "Critical" },
  high: { icon: "▲", color: "red", label: "High" },
  medium: { icon: "▲", color: "yellow", label: "Medium" },
  low: { icon: "•", color: "gray", label: "Low" }
};

const BAR_WIDTH = 44;

export function renderTerminalReport(result, palette, options = {}) {
  const { summary, project, stats, gatedRules, ai } = result;
  const lines = [];
  const active = activeFindings(result.findings);
  const groups = groupByRule(active);
  const limit = options.all ? groups.length : 12;

  lines.push("");
  lines.push(divider(palette));
  lines.push("");
  lines.push(`${palette.bold(`${project.name}`)} ${palette.dim(`· ${project.language} · ${project.framework} · ${project.relative}`)}`);
  lines.push("");

  if (!active.length) {
    lines.push(palette.green("  No findings. Every active rule ran clean."));
  } else {
    lines.push(`${palette.bold(`${active.length} ${pluralize(active.length, "finding")}`)}  ${categoryLine(summary, palette)}`);
    lines.push("");
    for (const group of groups.slice(0, limit)) {
      lines.push(...renderGroup(group, palette, options));
    }
    if (groups.length > limit) {
      lines.push(palette.dim(`  … ${groups.length - limit} more ${pluralize(groups.length - limit, "rule")} — rerun with --all to see every one.`));
      lines.push("");
    }
  }

  lines.push(scorecard(summary, palette));
  lines.push("");
  lines.push(palette.dim(`  ${stats.files} ${pluralize(stats.files, "file")} · ${stats.lines.toLocaleString()} lines scanned`));

  if (result.scope?.mode === "changed") {
    lines.push(palette.dim(`  Reporting only the ${result.scope.files} changed ${pluralize(result.scope.files, "file")} (${result.scope.base}). The whole project was analysed; findings elsewhere are not shown.`));
  }

  lines.push(...engineLines(result, palette));

  if (result.audit?.ran) {
    const total = result.audit.total;
    lines.push(palette.dim(`  ${result.audit.tool}: ${total} vulnerable ${pluralize(total, "dependency", "dependencies")}${result.audit.truncated ? `, ${result.audit.truncated} beyond the reporting limit` : ""}`));
  } else if (result.audit) {
    lines.push(palette.yellow(`  Dependency audit did not run: ${result.audit.reason}`));
  } else {
    lines.push(palette.dim("  Dependency vulnerabilities were not checked — add --audit to run the ecosystem auditor."));
  }

  if (ai?.used) {
    const detail = ai.reviewed
      ? `${ai.label} (${ai.model}) reviewed ${ai.reviewed} uncertain ${pluralize(ai.reviewed, "finding")}, refuting ${summary.refuted}`
      : `${ai.label} (${ai.model}) had nothing uncertain to review`;
    lines.push(palette.dim(`  ${detail}`));
    if (ai.truncated) {
      lines.push(palette.yellow(`  ${ai.truncated} uncertain ${pluralize(ai.truncated, "finding")} exceeded the triage budget and kept their pattern-match confidence.`));
    }
    for (const error of ai.errors || []) lines.push(palette.yellow(`  triage: ${error}`));
  } else if (ai?.reason) {
    lines.push(palette.dim(`  No model triage: ${ai.reason}`));
    lines.push(palette.dim("  Low-confidence findings below were not verified — treat them as leads, not conclusions."));
  }

  if (gatedRules.length) {
    const reasons = [...new Set(gatedRules.map((rule) => rule.reason))];
    lines.push(palette.dim(`  ${gatedRules.length} ${pluralize(gatedRules.length, "rule")} gated off (no ${reasons.join(", ")} usage detected). This is not the same as a clean scan.`));
  }

  lines.push("");
  lines.push(divider(palette));
  lines.push("");
  return lines.join("\n");
}

/**
 * What the external engines covered, and — the part worth printing — what nobody did.
 *
 * A harness that runs five tools and reports only their combined findings has hidden the
 * most useful fact it knows: which of the five was absent. That absence is the difference
 * between "no secrets found" and "no secrets found by the fourteen patterns Tripwire
 * ships, with no verification and no history scan", and the two must not read alike.
 */
function engineLines(result, palette) {
  const lines = [];
  if (!result.engines) {
    lines.push(palette.dim("  External engines were not run — add --engines to fold Semgrep, TruffleHog, osv-scanner and others into this report."));
    return lines;
  }

  const { coverage, uncovered, deduplicated, offline } = result.engines;
  const ran = coverage.filter((entry) => entry.ran);
  const failed = coverage.filter((entry) => entry.status === "failed");
  const needKey = coverage.filter((entry) => entry.status === "no-key");

  if (ran.length) {
    const detail = ran
      .map((entry) => `${entry.tool}${entry.total ? ` ${entry.total}` : " 0"}${entry.usedKey ? "*" : ""}`)
      .join(" · ");
    lines.push(palette.dim(`  Engines: ${detail}${offline ? "  (offline mode)" : ""}`));
    if (ran.some((entry) => entry.usedKey)) {
      lines.push(palette.dim(`  * authenticated with your own key from the environment`));
    }
    if (deduplicated) {
      lines.push(palette.dim(`  ${deduplicated} duplicate ${pluralize(deduplicated, "finding")} collapsed where engines agreed on the same line.`));
    }
    for (const entry of ran.filter((item) => item.truncated)) {
      lines.push(palette.yellow(`  ${entry.tool} reported ${entry.truncated} more beyond the per-engine reporting limit.`));
    }
  }

  for (const entry of failed) {
    lines.push(palette.yellow(`  ${entry.label} did not run: ${entry.reason}`));
  }
  for (const entry of needKey) {
    lines.push(palette.yellow(`  ${entry.label} is installed but unauthenticated: ${entry.reason}`));
  }
  // An engine you asked for and did not get must be named. Only "not selected" is silent,
  // because you already know what you did not ask for.
  for (const entry of coverage.filter((item) => item.status === "offline" || item.status === "disabled")) {
    lines.push(palette.yellow(`  ${entry.label} was skipped: ${entry.reason}`));
  }

  if (uncovered?.length) {
    for (const gap of uncovered) {
      lines.push(palette.dim(`  ${gap.label} had no engine — Tripwire's own coverage is ${gap.native}.`));
    }
  }
  return lines;
}

function renderGroup(group, palette, options) {
  const style = SEVERITY_STYLE[group.severity];
  const paint = palette[style.color];
  const count = group.findings.length;
  const lines = [];

  lines.push(`  ${paint(style.icon)} ${palette.bold(group.title)}${count > 1 ? palette.dim(` ×${count}`) : ""}  ${palette.dim(`${style.label} · ${CATEGORIES[group.category]?.label || group.category}`)}`);
  lines.push(`    ${wrap(group.why, 92, "    ")}`);
  lines.push(`    ${palette.cyan("→")} ${wrap(group.fix, 92, "    ")}`);
  lines.push("");

  const shown = options.all ? group.findings : group.findings.slice(0, 6);
  for (const finding of shown) {
    const marker = confidenceMarker(finding, palette);
    lines.push(`      ${palette.blue(`${finding.file}:${finding.line}`)}${marker}`);
    // The per-finding message carries what the rule title cannot: which value, which
    // route, which sink. For a reachability finding it *is* the finding, so printing
    // only the evidence line throws away the part worth reading.
    if (finding.message && finding.message !== group.title) {
      lines.push(`        ${wrap(stripMarkup(finding.message), 88, "        ")}`);
    }
    if (finding.evidence) lines.push(`        ${palette.dim(truncate(finding.evidence, 96))}`);
    // Provenance, so a finding you disagree with can be traced to the engine and the rule
    // that raised it rather than to "the scanner".
    if (finding.source) {
      const agreement = finding.corroboratedBy?.length ? `, confirmed by ${finding.corroboratedBy.join(", ")}` : "";
      lines.push(`        ${palette.dim(`via ${finding.source.label} · ${finding.source.ruleId}${agreement}`)}`);
    } else if (finding.corroboratedBy?.length) {
      lines.push(`        ${palette.dim(`confirmed by ${finding.corroboratedBy.join(", ")}`)}`);
    }
    if (finding.verdict?.reason) lines.push(`        ${palette.dim(`verified: ${truncate(finding.verdict.reason, 92)}`)}`);
  }
  if (group.findings.length > shown.length) {
    lines.push(palette.dim(`      … ${group.findings.length - shown.length} more`));
  }
  lines.push(`    ${palette.dim(group.ruleId)}`);
  lines.push("");
  return lines;
}

function confidenceMarker(finding, palette) {
  if (finding.verdict?.real === true) return palette.green("  confirmed");
  if (finding.confidence === "low") return palette.dim("  unverified");
  if (finding.confidence === "medium") return palette.dim("  likely");
  return "";
}

function categoryLine(summary, palette) {
  return Object.entries(summary.byCategory)
    .sort((a, b) => b[1] - a[1])
    .map(([category, count]) => palette.dim(`${CATEGORIES[category]?.label || category} ${count}`))
    .join(palette.dim(" · "));
}

function scorecard(summary, palette) {
  const filled = Math.round((summary.score / 100) * BAR_WIDTH);
  const color = summary.score >= 75 ? palette.green : summary.score >= 60 ? palette.yellow : palette.red;
  const bar = `${color("█".repeat(filled))}${palette.dim("░".repeat(BAR_WIDTH - filled))}`;
  return [
    "",
    `  ${palette.bold(color(String(summary.score).padStart(3)))} ${palette.dim("/ 100")}  ${palette.bold(summary.grade)}`,
    `  ${bar}`,
    `  ${palette.dim(`${summary.bySeverity.critical} critical · ${summary.bySeverity.high} high · ${summary.bySeverity.medium} medium · ${summary.bySeverity.low} low`)}`
  ].join("\n");
}

function divider(palette) {
  return palette.dim("─".repeat(78));
}

function stripMarkup(text) {
  return String(text).replace(/`/g, "");
}

function truncate(value, length) {
  const text = String(value).replace(/\s+/g, " ").trim();
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current && current.length + word.length + 1 > width) {
      lines.push(current);
      current = word;
      continue;
    }
    current = current ? `${current} ${word}` : word;
  }
  if (current) lines.push(current);
  return lines.join(`\n${indent}`);
}

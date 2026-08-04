import { CATEGORIES, SEVERITY_WEIGHT } from "./rules/index.js";

/**
 * Confidence multipliers. A low-confidence finding still counts — suppressing it
 * entirely would let the score hide real problems behind an uncertain match — but it
 * counts less than something the tool is sure about.
 */
const CONFIDENCE_WEIGHT = { high: 1, medium: 0.6, low: 0.3, refuted: 0 };

const GRADES = [
  { min: 90, label: "Healthy" },
  { min: 75, label: "Good" },
  { min: 60, label: "Needs work" },
  { min: 40, label: "At risk" },
  { min: 0, label: "Critical" }
];

/** Findings the model refuted are kept in the JSON output but excluded from everything else. */
export function activeFindings(findings) {
  return findings.filter((finding) => finding.verdict?.real !== false);
}

/**
 * Score a project out of 100.
 *
 * Two things are deliberately true about this number. It is density-based, so a large
 * repository is not punished for being large — otherwise every mature codebase scores
 * zero and the number stops carrying information. And it is capped from above by the
 * worst finding present, so a single committed credential cannot be averaged away by
 * thousands of clean lines.
 */
export function scoreProject(findings, stats) {
  const active = activeFindings(findings);
  const kilolines = Math.max(1, (stats.lines || 1) / 1000);

  let penalty = 0;
  const byCategory = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const finding of active) {
    const categoryWeight = CATEGORIES[finding.category]?.weight ?? 0.5;
    const confidenceWeight = CONFIDENCE_WEIGHT[finding.confidence] ?? 0.6;
    penalty += SEVERITY_WEIGHT[finding.severity] * categoryWeight * confidenceWeight;

    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
  }

  const density = penalty / kilolines;
  let score = Math.round(100 / (1 + density / 6));

  // Ceilings: the presence of a serious confirmed issue bounds the score regardless of
  // how healthy the rest of the codebase is.
  const confirmed = (severity) => active.some((finding) =>
    finding.severity === severity && (finding.confidence === "high" || finding.verdict?.real === true));
  if (confirmed("critical")) score = Math.min(score, 55);
  else if (confirmed("high")) score = Math.min(score, 78);

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    grade: GRADES.find((grade) => score >= grade.min).label,
    total: active.length,
    refuted: findings.length - active.length,
    byCategory,
    bySeverity,
    density: Math.round(density * 10) / 10
  };
}

/** Group findings by rule so the report shows one entry per rule with its sites listed. */
export function groupByRule(findings) {
  const groups = new Map();
  for (const finding of findings) {
    if (!groups.has(finding.ruleId)) {
      groups.set(finding.ruleId, {
        ruleId: finding.ruleId,
        category: finding.category,
        severity: finding.severity,
        title: finding.title,
        why: finding.why,
        fix: finding.fix,
        findings: []
      });
    }
    const group = groups.get(finding.ruleId);
    group.findings.push(finding);
    // A group takes the severity of its worst member, since rules can override per finding.
    if (rank(finding.severity) < rank(group.severity)) group.severity = finding.severity;
  }
  return [...groups.values()].sort((a, b) =>
    rank(a.severity) - rank(b.severity)
    || b.findings.length - a.findings.length
    || a.ruleId.localeCompare(b.ruleId));
}

function rank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

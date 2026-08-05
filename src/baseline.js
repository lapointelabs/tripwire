import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { activeFindings } from "./score.js";

export const BASELINE_SCHEMA_VERSION = 1;

/**
 * A location-stable identity for a finding.
 *
 * Line numbers are intentionally excluded: inserting a header should not turn every known
 * alert below it into a new regression. Evidence is normalized so formatting-only changes
 * survive too. The source rule remains part of the identity because two engines can make
 * materially different claims about the same line.
 */
export function fingerprintFinding(finding) {
  const evidence = normalize(finding.evidence || finding.message || finding.title);
  const identity = [
    finding.ruleId,
    finding.source?.engine || "tripwire",
    finding.source?.ruleId || finding.ruleId,
    String(finding.file || "").replace(/\\/g, "/"),
    evidence
  ].join("\u0000");
  return createHash("sha256").update(identity).digest("hex");
}

export async function readBaseline(root, value) {
  if (!value) return null;
  const file = path.resolve(root, String(value));
  let document;
  try {
    document = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`could not read baseline ${file}: ${error.message}`);
  }
  if (document?.schemaVersion !== BASELINE_SCHEMA_VERSION || !Array.isArray(document.findings)) {
    throw new Error(`baseline ${file} is not a Tripwire baseline schema v${BASELINE_SCHEMA_VERSION}`);
  }
  return { file, document };
}

/**
 * Mark findings as new or unchanged and return known findings that disappeared.
 *
 * Baselines are multisets. If identical evidence occurs twice in a file and only one copy
 * remains, the comparison consumes one entry and reports the other as resolved.
 */
export function compareBaseline(result, baseline) {
  const project = result.project.relative;
  const known = baseline.document.findings.filter((entry) => entry.project === project);
  const buckets = new Map();
  for (const entry of known) {
    const list = buckets.get(entry.fingerprint) || [];
    list.push(entry);
    buckets.set(entry.fingerprint, list);
  }

  let newCount = 0;
  let unchanged = 0;
  for (const finding of activeFindings(result.findings)) {
    const fingerprint = fingerprintFinding(finding);
    finding.fingerprint = fingerprint;
    const matches = buckets.get(fingerprint);
    if (matches?.length) {
      finding.baselineState = "unchanged";
      matches.shift();
      unchanged += 1;
    } else {
      finding.baselineState = "new";
      newCount += 1;
    }
  }

  const resolved = [...buckets.values()].flat();
  const newBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of activeFindings(result.findings)) {
    if (finding.baselineState === "new") newBySeverity[finding.severity] += 1;
  }

  result.baseline = {
    file: baseline.file,
    createdAt: baseline.document.createdAt || null,
    new: newCount,
    unchanged,
    resolved: resolved.length,
    newBySeverity,
    resolvedFindings: resolved
  };
  return result.baseline;
}

export function createBaseline(results, meta = {}) {
  const findings = [];
  for (const result of results) {
    for (const finding of activeFindings(result.findings)) {
      findings.push({
        fingerprint: fingerprintFinding(finding),
        project: result.project.relative,
        ruleId: finding.ruleId,
        source: finding.source?.engine || "tripwire",
        sourceRuleId: finding.source?.ruleId || finding.ruleId,
        severity: finding.severity,
        file: finding.file,
        line: finding.line,
        title: finding.title
      });
    }
  }
  findings.sort((a, b) => a.project.localeCompare(b.project)
    || a.file.localeCompare(b.file)
    || a.line - b.line
    || a.ruleId.localeCompare(b.ruleId));
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    tripwireVersion: meta.version || null,
    createdAt: meta.scannedAt || new Date().toISOString(),
    findings
  };
}

export async function writeBaseline(file, results, meta) {
  const absolute = path.resolve(file);
  const document = createBaseline(results, meta);
  await writeFile(absolute, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  return { file: absolute, count: document.findings.length };
}

function normalize(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

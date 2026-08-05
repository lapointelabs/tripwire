import { readFile } from "node:fs/promises";
import path from "node:path";
import { capabilitiesOf, findAgentContextFiles } from "./detect.js";
import { crossProjectRules, fileRules, projectRules, rulesForLanguage, selectRules } from "./rules/index.js";
import { relevantForTaint } from "./rules/taint.js";
import { prepareFile } from "./source.js";
import { compileIgnorePatterns, mapWithConcurrency, readJson, readText, relativePath, walkSourceFiles } from "./util.js";

const READ_CONCURRENCY = 24;

/**
 * Scan one project and return raw findings. Everything here is deterministic: the same
 * tree produces the same findings in the same order, which is what makes the results
 * usable as a baseline in CI and as a diff between runs.
 */
export async function scanProject(options) {
  const { root, project, only = [], skip = [], onProgress = () => {}, maxFiles = 5000, excludePaths = [] } = options;
  const capabilities = capabilitiesOf(project);

  const gitignore = await readText(path.join(root, ".gitignore"));
  const ignoreRules = compileIgnorePatterns(gitignore);
  const files = await walkSourceFiles(project.directory, { ignoreRules, limit: maxFiles, excludePaths });

  const fileSelection = selectRules(fileRules, { capabilities, only, skip });
  const projectSelection = selectRules(projectRules, { capabilities, only, skip });

  const findings = [];
  const preparedFiles = [];
  let scanned = 0;

  await mapWithConcurrency(files, READ_CONCURRENCY, async (file) => {
    let text;
    try {
      text = await readFile(file.absolute, "utf8");
    } catch {
      return;
    }
    // A file with a NUL byte in the first block is binary regardless of its extension.
    if (text.indexOf("\u0000") !== -1) return;

    const prepared = prepareFile({ ...file, relative: relativePath(root, file.absolute) }, text);
    preparedFiles.push(prepared);

    for (const rule of rulesForLanguage(fileSelection.active, file.language)) {
      let raw;
      try {
        raw = rule.scan(prepared) || [];
      } catch (error) {
        // A rule that throws must not take the scan down with it.
        onProgress({ kind: "rule-error", rule: rule.id, file: prepared.relative, message: error.message });
        continue;
      }
      for (const item of raw) {
        findings.push(toFinding(rule, prepared.relative, item));
      }
    }

    scanned += 1;
    onProgress({ kind: "file", scanned, total: files.length, file: prepared.relative });
  });

  const agentFiles = await findAgentContextFiles(root);
  const packageJson = project.kind === "node" ? await readJson(path.join(project.directory, "package.json")) : null;
  const projectContext = {
    root,
    project,
    projectRelative: project.relative,
    files,
    preparedFiles,
    agentFiles,
    scripts: new Set(Object.keys(packageJson?.scripts || {})),
    knownPaths: new Set(files.map((file) => relativePath(root, file.absolute))),
    symbolReferences: countIdentifiers(preparedFiles)
  };

  for (const rule of projectSelection.active) {
    let raw;
    try {
      raw = (await rule.scanProject(projectContext)) || [];
    } catch (error) {
      onProgress({ kind: "rule-error", rule: rule.id, file: project.relative, message: error.message });
      continue;
    }
    for (const item of raw) {
      findings.push(toFinding(rule, item.file || project.relative, item));
    }
  }

  findings.sort(compareFindings);
  return {
    project,
    capabilities,
    // Retained for the cross-project pass. Only files that bind request data or hold a
    // sink are kept, so the union across a large solution stays small.
    taintCandidates: preparedFiles.filter(relevantForTaint),
    findings: dedupe(findings),
    stats: {
      files: files.length,
      lines: preparedFiles.reduce((total, file) => total + file.lines.length, 0),
      languages: countBy(files, (file) => file.language)
    },
    gatedRules: [...fileSelection.gated, ...projectSelection.gated].map(({ rule, reason }) => ({ id: rule.id, title: rule.title, reason })),
    agentFiles: agentFiles.map((entry) => entry.relative)
  };
}

function toFinding(rule, file, item) {
  return {
    id: `${rule.id}:${file}:${item.line}`,
    ruleId: rule.id,
    category: rule.category,
    severity: item.severity || rule.severity,
    title: rule.title,
    why: rule.why,
    fix: rule.fix,
    file,
    line: item.line,
    endLine: item.endLine || item.line,
    evidence: item.evidence || "",
    message: item.message || rule.title,
    confidence: item.confidence || rule.confidence || "medium",
    aiTriage: Boolean(rule.aiTriage) || (item.confidence || rule.confidence) !== "high",
    verdict: null
  };
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export function compareFindings(a, b) {
  const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  if (bySeverity !== 0) return bySeverity;
  if (a.file !== b.file) return a.file.localeCompare(b.file);
  if (a.line !== b.line) return a.line - b.line;
  return a.ruleId.localeCompare(b.ruleId);
}

function dedupe(findings) {
  const seen = new Set();
  const result = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    result.push(finding);
  }
  return result;
}

function countBy(items, pick) {
  const counts = {};
  for (const item of items) {
    const key = pick(item);
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

/**
 * Frequency of every identifier across the project. Used to tell a genuinely unused
 * export from one reached through dynamic dispatch or a string-keyed registry.
 */
function countIdentifiers(preparedFiles) {
  const counts = new Map();
  for (const file of preparedFiles) {
    for (const match of file.code.matchAll(/[A-Za-z_$][\w$]{2,}/g)) {
      counts.set(match[0], (counts.get(match[0]) || 0) + 1);
    }
  }
  return counts;
}

/**
 * Run rules that need the whole solution at once, after every project has been scanned.
 *
 * Findings are attributed to the project that owns the entry-point file, so a chain from
 * a controller in one assembly into a helper in another is reported where someone would
 * go to fix it — at the route that exposes it.
 */
export async function scanAcrossProjects(results, { only = [], skip = [], onProgress = () => {} } = {}) {
  const selection = selectRules(crossProjectRules, { capabilities: { ai: true, database: true, web: true }, only, skip });
  if (!selection.active.length || results.length === 0) return;

  const files = results.flatMap((result) => result.taintCandidates || []);
  if (!files.length) return;

  for (const rule of selection.active) {
    let raw;
    try {
      raw = (await rule.scanCross({ files, projects: results.map((result) => result.project) })) || [];
    } catch (error) {
      onProgress({ kind: "rule-error", rule: rule.id, message: error.message });
      continue;
    }
    for (const item of raw) {
      // Attribute to the project whose file the entry point lives in.
      const owner = results.find((result) => (result.taintCandidates || []).some((file) => file.relative === item.file))
        || results[0];
      owner.findings.push(toFinding(rule, item.file, item));
      owner.findings.sort(compareFindings);
    }
  }
}

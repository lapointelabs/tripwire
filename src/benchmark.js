import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { detectProjects } from "./detect.js";
import { activeFindings } from "./score.js";
import { scanProject } from "./scan.js";

export const DEFAULT_BENCHMARK_ROOT = fileURLToPath(new URL("../benchmark/", import.meta.url));

/** Run a labeled corpus through the deterministic scanner and calculate honest metrics. */
export async function runBenchmark(root = DEFAULT_BENCHMARK_ROOT) {
  const started = Date.now();
  const { directory, manifest } = await loadManifest(root);
  const cases = [];

  for (const definition of manifest.cases) {
    const caseRoot = safeChild(directory, definition.path);
    const projects = await detectProjects(caseRoot);
    const candidates = projects.filter((project) => !project.isWorkspaceRoot);
    const pool = candidates.length ? candidates : projects;
    const project = definition.project
      ? pool.find((entry) => entry.name === definition.project || entry.relative === definition.project)
      : pool[0];
    if (!project) throw new Error(`benchmark case "${definition.id}" contains no detected project`);

    const result = await scanProject({
      root: caseRoot,
      project,
      only: strings(definition.only),
      skip: strings(definition.skip)
    });
    const evaluation = evaluate(activeFindings(result.findings), definition.expectations || [], definition.lineTolerance || 0);
    cases.push({
      id: definition.id,
      title: definition.title || definition.id,
      description: definition.description || "",
      project: project.relative,
      stats: result.stats,
      ...evaluation
    });
  }

  const totals = sumMetrics(cases);
  const perRule = ruleMetrics(cases);
  return {
    schemaVersion: 1,
    corpus: {
      name: manifest.name,
      version: manifest.version,
      description: manifest.description || "",
      cases: cases.length
    },
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    summary: withRates(totals),
    perRule,
    cases
  };
}

export function evaluate(findings, expectations, tolerance = 0) {
  const remaining = findings.map((finding, index) => ({ finding, index }));
  const matches = [];
  const missed = [];

  for (const expected of expectations) {
    const index = remaining.findIndex(({ finding }) => finding.ruleId === expected.ruleId
      && finding.file === expected.file
      && Math.abs(finding.line - expected.line) <= (expected.lineTolerance ?? tolerance));
    if (index === -1) {
      missed.push(expected);
      continue;
    }
    matches.push({ expected, finding: remaining[index].finding });
    remaining.splice(index, 1);
  }

  const unexpected = remaining.map(({ finding }) => finding);
  return {
    metrics: withRates({ truePositive: matches.length, falsePositive: unexpected.length, falseNegative: missed.length }),
    matches,
    missed,
    unexpected
  };
}

export function renderBenchmarkHtml(result, meta = {}) {
  const metrics = result.summary;
  const max = Math.max(1, ...result.perRule.map((row) => Math.max(row.expected, row.predicted)));
  const rules = result.perRule.map((row) => `<tr><td><code>${escapeHtml(row.ruleId)}</code></td><td>${row.truePositive}/${row.expected}</td><td>${row.falsePositive}</td><td><div class="track" aria-label="${percent(row.recall)} recall"><i style="width:${row.recall * 100}%"></i></div></td></tr>`).join("");
  const cases = result.cases.map((entry) => `<tr><td><strong>${escapeHtml(entry.title)}</strong><small>${escapeHtml(entry.description)}</small></td><td>${entry.metrics.truePositive}</td><td>${entry.metrics.falsePositive}</td><td>${entry.metrics.falseNegative}</td><td>${percent(entry.metrics.f1)}</td></tr>`).join("");
  const width = (value) => Math.max(value ? 2 : 0, (value / max) * 100);

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tripwire benchmark — ${escapeHtml(result.corpus.name)}</title><style>
:root{color-scheme:light dark;--bg:#f5f4ef;--panel:#fff;--ink:#171716;--muted:#66645e;--line:#d9d6cc;--accent:#3157a4;--good:#237a46;--bad:#a92525;--soft:#ece9df}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1060px;margin:auto;padding:42px 24px 64px}h1,h2{margin:0;letter-spacing:-.025em}h1{font-size:30px}h2{font-size:18px;margin-bottom:14px}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:700;color:var(--muted)}.meta,small{display:block;color:var(--muted);margin-top:6px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.metric,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px}.metric{padding:17px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{font-size:26px;font-variant-numeric:tabular-nums}.panel{padding:20px;margin:16px 0}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.track{width:100%;min-width:120px;height:9px;border-radius:9px;background:var(--soft);overflow:hidden}.track i{height:100%;display:block;background:var(--good)}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.legend{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);margin-top:14px}.legend b{color:var(--ink)}.rule-bars{display:grid;grid-template-columns:220px 1fr 44px;align-items:center;gap:10px;margin:9px 0}.rule-bars .track i{background:var(--accent)}footer{color:var(--muted);font-size:12px;margin-top:20px}@media(max-width:700px){main{padding:24px 14px}.metrics{grid-template-columns:1fr 1fr}.table-wrap{overflow-x:auto}.rule-bars{grid-template-columns:150px 1fr 38px}}@media(prefers-color-scheme:dark){:root{--bg:#11120f;--panel:#1b1c18;--ink:#f2f1eb;--muted:#aaa89f;--line:#36372f;--soft:#292a24;--accent:#8aa7e8;--good:#6ec990}}
</style></head><body><main><div class="eyebrow">Tripwire benchmark</div><h1>${escapeHtml(result.corpus.name)}</h1><p class="meta">Corpus ${escapeHtml(result.corpus.version)} · ${result.corpus.cases} case${result.corpus.cases === 1 ? "" : "s"} · ${result.durationMs} ms${meta.version ? ` · Tripwire ${escapeHtml(meta.version)}` : ""}<br>${escapeHtml(result.corpus.description)}</p>
<section class="metrics"><div class="metric"><span>Precision</span><strong>${percent(metrics.precision)}</strong></div><div class="metric"><span>Recall</span><strong>${percent(metrics.recall)}</strong></div><div class="metric"><span>F1</span><strong>${percent(metrics.f1)}</strong></div><div class="metric"><span>Unexpected</span><strong>${metrics.falsePositive}</strong></div></section>
<section class="panel"><h2>Rule recall</h2>${result.perRule.map((row) => `<div class="rule-bars"><code>${escapeHtml(row.ruleId)}</code><div class="track"><i style="width:${width(row.truePositive)}%"></i></div><strong>${row.truePositive}/${row.expected}</strong></div>`).join("")}</section>
<section class="panel"><h2>Per-rule detail</h2><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Detected</th><th>Unexpected</th><th>Recall</th></tr></thead><tbody>${rules}</tbody></table></div></section>
<section class="panel"><h2>Cases</h2><div class="table-wrap"><table><thead><tr><th>Case</th><th>TP</th><th>FP</th><th>FN</th><th>F1</th></tr></thead><tbody>${cases}</tbody></table></div></section>
<footer>This is a versioned, seeded regression corpus maintained with Tripwire. It measures the labeled cases shown here; it is not an independent comparison or a claim about real-world vulnerability prevalence.</footer></main></body></html>`;
}

async function loadManifest(root) {
  const resolved = path.resolve(root);
  const file = path.extname(resolved) === ".json" ? resolved : path.join(resolved, "manifest.json");
  let manifest;
  try {
    manifest = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`could not read benchmark manifest ${file}: ${error.message}`);
  }
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.cases)) {
    throw new Error(`benchmark manifest ${file} must use schemaVersion 1 and contain a cases array`);
  }
  return { directory: path.dirname(file), manifest };
}

function safeChild(root, relative) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, String(relative || "."));
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`benchmark case path escapes the corpus: ${relative}`);
  }
  return resolved;
}

function sumMetrics(cases) {
  return cases.reduce((total, entry) => ({
    truePositive: total.truePositive + entry.metrics.truePositive,
    falsePositive: total.falsePositive + entry.metrics.falsePositive,
    falseNegative: total.falseNegative + entry.metrics.falseNegative
  }), { truePositive: 0, falsePositive: 0, falseNegative: 0 });
}

function ruleMetrics(cases) {
  const rows = new Map();
  const row = (ruleId) => {
    if (!rows.has(ruleId)) rows.set(ruleId, { ruleId, expected: 0, predicted: 0, truePositive: 0, falsePositive: 0, falseNegative: 0 });
    return rows.get(ruleId);
  };
  for (const entry of cases) {
    for (const { expected } of entry.matches) {
      row(expected.ruleId).expected += 1;
      row(expected.ruleId).predicted += 1;
      row(expected.ruleId).truePositive += 1;
    }
    for (const expected of entry.missed) {
      row(expected.ruleId).expected += 1;
      row(expected.ruleId).falseNegative += 1;
    }
    for (const finding of entry.unexpected) {
      row(finding.ruleId).predicted += 1;
      row(finding.ruleId).falsePositive += 1;
    }
  }
  return [...rows.values()].map((entry) => ({ ...entry, ...withRates(entry) }))
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
}

function withRates(metrics) {
  const precision = divide(metrics.truePositive, metrics.truePositive + metrics.falsePositive);
  const recall = divide(metrics.truePositive, metrics.truePositive + metrics.falseNegative);
  return { ...metrics, precision, recall, f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0 };
}

function divide(value, total) {
  return total ? value / total : 1;
}

function strings(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function percent(value) {
  return `${Math.round(value * 1000) / 10}%`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  })[character]);
}

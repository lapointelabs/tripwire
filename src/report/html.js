import { CATEGORIES } from "../rules/index.js";
import { activeFindings } from "../score.js";

const SEVERITIES = ["critical", "high", "medium", "low"];

/** A self-contained report that can be archived as CI evidence or opened locally. */
export function renderReportHtml(result, meta) {
  const findings = activeFindings(result.findings);
  const maxCategory = Math.max(1, ...Object.values(result.summary.byCategory));
  const engineRows = result.engines?.coverage || [];
  const baseline = result.baseline;

  const severityBars = SEVERITIES.map((severity) => {
    const count = result.summary.bySeverity[severity] || 0;
    const width = findings.length ? Math.max(count ? 3 : 0, (count / findings.length) * 100) : 0;
    return `<div class="bar-row"><span>${title(severity)}</span><div class="track"><i class="fill ${severity}" style="width:${width}%"></i></div><strong>${count}</strong></div>`;
  }).join("");

  const categories = Object.entries(result.summary.byCategory)
    .sort((a, b) => b[1] - a[1])
    .map(([category, count]) => `<div class="bar-row"><span>${escapeHtml(CATEGORIES[category]?.label || category)}</span><div class="track"><i class="fill category" style="width:${Math.max(3, (count / maxCategory) * 100)}%"></i></div><strong>${count}</strong></div>`)
    .join("") || `<p class="muted">No active findings.</p>`;

  const coverage = engineRows.length
    ? engineRows.map((entry) => `<tr><td>${escapeHtml(entry.label)}</td><td><span class="status ${entry.ran ? "ran" : "skipped"}">${entry.ran ? "Ran" : title(entry.status)}</span></td><td>${entry.ran ? `${entry.total} finding${entry.total === 1 ? "" : "s"}` : escapeHtml(entry.reason || "Not run")}</td></tr>`).join("")
    : `<tr><td colspan="3">External engines were not requested.</td></tr>`;

  const rows = findings.map((finding) => `<tr data-finding data-severity="${finding.severity}" data-new="${finding.baselineState === "new" ? "true" : "false"}">
    <td><span class="severity ${finding.severity}">${title(finding.severity)}</span>${finding.baselineState === "new" ? ` <span class="new">New</span>` : ""}</td>
    <td><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.ruleId)}${finding.source ? ` · ${escapeHtml(finding.source.label)}` : ""}</small></td>
    <td><code>${escapeHtml(finding.file)}:${finding.line}</code><small>${escapeHtml(finding.evidence || finding.message || "")}</small></td>
    <td>${escapeHtml(confidence(finding))}</td>
  </tr>`).join("") || `<tr><td colspan="4">No active findings.</td></tr>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tripwire report — ${escapeHtml(result.project.name)}</title>
<style>
:root{color-scheme:light dark;--bg:#f5f4ef;--panel:#fff;--ink:#171716;--muted:#66645e;--line:#d9d6cc;--critical:#a92525;--high:#d35a23;--medium:#b58213;--low:#667085;--accent:#3157a4;--ok:#237a46;--soft:#ece9df}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1160px;margin:auto;padding:40px 24px 64px}header{display:flex;align-items:center;justify-content:space-between;gap:32px;border-bottom:1px solid var(--line);padding-bottom:28px}h1,h2{font-weight:650;letter-spacing:-.025em;margin:0}h1{font-size:30px}h2{font-size:18px;margin-bottom:16px}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;color:var(--muted);font-weight:700}.meta,.muted,small{color:var(--muted)}.meta{margin:8px 0 0}.score{--value:${result.summary.score * 3.6}deg;width:118px;height:118px;border-radius:50%;background:conic-gradient(var(--accent) var(--value),var(--soft) 0);display:grid;place-items:center;position:relative;flex:0 0 auto}.score:after{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--panel)}.score div{position:relative;z-index:1;text-align:center}.score strong{display:block;font-size:30px;line-height:1}.score span{color:var(--muted);font-size:12px}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0}.metric,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px}.metric{padding:16px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{font-size:24px;font-variant-numeric:tabular-nums}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{padding:20px;margin-bottom:16px}.bar-row{display:grid;grid-template-columns:130px 1fr 28px;gap:10px;align-items:center;margin:10px 0}.track{height:9px;background:var(--soft);border-radius:9px;overflow:hidden}.fill{display:block;height:100%;background:var(--low)}.fill.critical{background:var(--critical)}.fill.high{background:var(--high)}.fill.medium{background:var(--medium)}.fill.category{background:var(--accent)}.bar-row strong{text-align:right;font-variant-numeric:tabular-nums}.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}input,select{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px}input{min-width:260px;flex:1}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}td small{display:block;margin-top:4px;max-width:600px}.severity,.status,.new{display:inline-block;border-radius:99px;padding:2px 8px;font-size:11px;font-weight:700}.severity{color:#fff}.severity.critical{background:var(--critical)}.severity.high{background:var(--high)}.severity.medium{background:var(--medium)}.severity.low{background:var(--low)}.status.ran{color:var(--ok);background:color-mix(in srgb,var(--ok) 13%,transparent)}.status.skipped{color:var(--muted);background:var(--soft)}.new{color:var(--accent);background:color-mix(in srgb,var(--accent) 13%,transparent)}code{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}.empty{display:none;text-align:center;color:var(--muted);padding:24px}footer{margin-top:24px;color:var(--muted);font-size:12px}@media(max-width:760px){main{padding:24px 14px}header{align-items:flex-start}.summary{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}.score{width:92px;height:92px}.table-wrap{overflow-x:auto}th,td{min-width:120px}.bar-row{grid-template-columns:105px 1fr 24px}}@media(prefers-color-scheme:dark){:root{--bg:#11120f;--panel:#1b1c18;--ink:#f2f1eb;--muted:#aaa89f;--line:#36372f;--soft:#292a24;--accent:#8aa7e8;--ok:#6ec990}}@media print{body{background:#fff;color:#111}main{max-width:none;padding:0}.controls{display:none}.panel,.metric{break-inside:avoid}}
</style></head><body><main>
<header><div><div class="eyebrow">Tripwire security report</div><h1>${escapeHtml(result.project.name)}</h1><p class="meta">${escapeHtml(result.project.language)} · ${escapeHtml(result.project.framework)} · <code>${escapeHtml(result.project.relative)}</code><br>${escapeHtml(meta.scannedAt)} · Tripwire ${escapeHtml(meta.version)}</p></div><div class="score" aria-label="Score ${result.summary.score} out of 100"><div><strong>${result.summary.score}</strong><span>${escapeHtml(result.summary.grade)}</span></div></div></header>
<section class="summary" aria-label="Summary"><div class="metric"><span>Active findings</span><strong>${findings.length}</strong></div><div class="metric"><span>New since baseline</span><strong>${baseline ? baseline.new : "—"}</strong></div><div class="metric"><span>Files scanned</span><strong>${result.stats.files}</strong></div><div class="metric"><span>Lines scanned</span><strong>${result.stats.lines.toLocaleString()}</strong></div></section>
<div class="grid"><section class="panel"><h2>Severity</h2>${severityBars}</section><section class="panel"><h2>Categories</h2>${categories}</section></div>
<section class="panel"><h2>Coverage</h2><div class="table-wrap"><table><thead><tr><th>Engine</th><th>Status</th><th>Detail</th></tr></thead><tbody>${coverage}</tbody></table></div></section>
<section class="panel"><h2>Findings</h2><div class="controls"><label class="eyebrow" for="query">Filter findings</label><input id="query" type="search" placeholder="Rule, file, or evidence"><select id="severity" aria-label="Severity"><option value="">All severities</option>${SEVERITIES.map((value) => `<option value="${value}">${title(value)}</option>`).join("")}</select>${baseline ? `<select id="baseline" aria-label="Baseline state"><option value="">All baseline states</option><option value="true">New only</option><option value="false">Known only</option></select>` : ""}</div><div class="table-wrap"><table id="findings"><thead><tr><th>Risk</th><th>Finding</th><th>Location and evidence</th><th>Confidence</th></tr></thead><tbody>${rows}</tbody></table></div><div class="empty" id="empty">No findings match these filters.</div></section>
<footer>Generated locally. Source and secret values are not embedded beyond the redacted evidence already present in Tripwire findings.${baseline ? ` Baseline: ${escapeHtml(baseline.file)} · ${baseline.unchanged} known · ${baseline.resolved} resolved.` : ""}</footer>
</main><script>(()=>{const q=document.getElementById('query'),s=document.getElementById('severity'),b=document.getElementById('baseline'),rows=[...document.querySelectorAll('[data-finding]')],empty=document.getElementById('empty');function filter(){const text=q.value.trim().toLowerCase();let shown=0;for(const row of rows){const visible=(!text||row.textContent.toLowerCase().includes(text))&&(!s.value||row.dataset.severity===s.value)&&(!b||!b.value||row.dataset.new===b.value);row.hidden=!visible;if(visible)shown++}empty.style.display=rows.length&&!shown?'block':'none'}q.addEventListener('input',filter);s.addEventListener('change',filter);b?.addEventListener('change',filter)})();</script></body></html>`;
}

function confidence(finding) {
  if (finding.verdict?.real === true) return `Confirmed (${finding.verdict.confidence})`;
  return { high: "High", medium: "Likely", low: "Unverified" }[finding.confidence] || finding.confidence;
}

function title(value) {
  const text = String(value || "").replace(/-/g, " ");
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  })[character]);
}

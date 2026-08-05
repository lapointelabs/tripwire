import { readFile } from "node:fs/promises";
import path from "node:path";
import { findingsFromSarif } from "./sarif.js";
import { relativizer, toFinding } from "./index.js";

/** Import CodeQL or any other SARIF 2.1 producer without making it a hard-wired engine. */
export async function importSarifReports(root, values) {
  const findings = [];
  const coverage = [];
  const toRelative = relativizer(root);

  for (const value of values) {
    const file = path.resolve(root, String(value));
    let document;
    try {
      document = JSON.parse(await readFile(file, "utf8"));
    } catch (error) {
      throw new Error(`could not import SARIF ${file}: ${error.message}`);
    }
    if (document?.version !== "2.1.0" || !Array.isArray(document.runs)) {
      throw new Error(`could not import SARIF ${file}: expected a SARIF 2.1.0 runs array`);
    }

    const labels = [...new Set(document.runs.map((run) => run.tool?.driver?.name).filter(Boolean))];
    const label = labels.join(" + ") || path.basename(file);
    const engine = {
      id: `sarif-${slug(label)}`,
      label,
      domain: "code"
    };
    const imported = findingsFromSarif(document, { toRelative, engine: engine.id })
      .map((item) => {
        const domain = importedDomain(item);
        return domain === "secrets"
          ? { ...item, domain, title: `Credential reported by ${label}`, evidence: "credential value withheld", message: `${label} reported a credential at this location (${item.externalRuleId}); the value was withheld.` }
          : { ...item, domain };
      });
    findings.push(...imported.map((item) => toFinding(item, engine)));
    coverage.push({
      id: engine.id,
      label,
      domain: "code",
      covers: `findings imported from ${path.basename(file)}`,
      ran: true,
      status: "imported",
      tool: label,
      total: imported.length,
      truncated: 0,
      usedKey: false,
      reason: null
    });
  }

  return { findings, coverage };
}

function importedDomain(item) {
  const value = `${item.externalRuleId} ${(item.tags || []).join(" ")}`.toLowerCase();
  if (/secret|credential|token/.test(value)) return "secrets";
  if (/dependenc|package|cve|advisory/.test(value)) return "deps";
  if (/\bmcp\b|skill|prompt|agent/.test(value)) return "agent-surface";
  return "code";
}

function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "external";
}

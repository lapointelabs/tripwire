import { allRules } from "../rules/index.js";
import { activeFindings } from "../score.js";

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };

/** SARIF 2.1.0, so findings surface in GitHub code scanning without a bespoke action. */
export function renderSarif(result, meta) {
  const active = activeFindings(result.findings);
  const usedRuleIds = [...new Set(active.map((finding) => finding.ruleId))];
  const rules = usedRuleIds
    .map((id) => allRules.find((rule) => rule.id === id))
    .filter(Boolean)
    .map((rule) => ({
      id: rule.id,
      name: rule.id.replace(/[^A-Za-z0-9]/g, ""),
      shortDescription: { text: rule.title },
      fullDescription: { text: rule.why },
      help: { text: `${rule.why}\n\n${rule.fix}`, markdown: `${rule.why}\n\n**Fix.** ${rule.fix}` },
      properties: {
        category: rule.category,
        "security-severity": securitySeverity(rule.severity),
        tags: [rule.category, ...(rule.category === "security" ? ["security"] : [])]
      },
      defaultConfiguration: { level: SARIF_LEVEL[rule.severity] || "warning" }
    }));

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Tripwire",
          version: meta.version,
          informationUri: "https://github.com/lapointelabs/tripwire",
          rules
        }
      },
      results: active.map((finding) => ({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.severity] || "warning",
        message: { text: finding.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.file },
            region: {
              startLine: finding.line,
              endLine: Math.max(finding.line, finding.endLine || finding.line),
              snippet: finding.evidence ? { text: finding.evidence } : undefined
            }
          }
        }],
        properties: {
          confidence: finding.confidence,
          triaged: Boolean(finding.verdict),
          triageReason: finding.verdict?.reason,
          // Uploading someone else's findings under your own tool's name, with no trace of
          // where they came from, is how a security dashboard becomes unauditable.
          engine: finding.source?.engine,
          engineRuleId: finding.source?.ruleId,
          verifiedCredential: finding.source?.verified,
          corroboratedBy: finding.corroboratedBy?.length ? finding.corroboratedBy : undefined
        }
      }))
    }]
  };
}

function securitySeverity(severity) {
  return { critical: "9.0", high: "7.5", medium: "5.0", low: "2.0" }[severity] || "5.0";
}

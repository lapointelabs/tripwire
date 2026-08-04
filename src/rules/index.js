import { contextProjectRules, contextRules } from "./context.js";
import { injectionRules } from "./injection.js";
import { llmRules } from "./llm.js";
import { secretRules } from "./secrets.js";
import { structureProjectRules, structureRules } from "./structure.js";
import { supplyChainProjectRules } from "./supply-chain.js";
import { VULNERABLE_DEPENDENCY_RULE } from "../audit.js";
import { taintCrossProjectRules } from "./taint.js";
import { telemetryProjectRules, telemetryRules } from "./telemetry.js";
import { webRules } from "./web.js";

export const CATEGORIES = {
  security: { label: "Security", weight: 1 },
  privacy: { label: "Privacy", weight: 1 },
  "supply-chain": { label: "Supply chain", weight: 0.8 },
  "agent-safety": { label: "Agent safety", weight: 1 },
  correctness: { label: "Correctness", weight: 0.8 },
  maintainability: { label: "Maintainability", weight: 0.4 },
  performance: { label: "Performance", weight: 0.4 }
};

export const SEVERITIES = ["critical", "high", "medium", "low"];

export const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 3, low: 1 };

export const fileRules = [
  ...injectionRules,
  ...webRules,
  ...secretRules,
  ...telemetryRules,
  ...llmRules,
  ...contextRules,
  ...structureRules
];

export const projectRules = [
  ...contextProjectRules,
  ...supplyChainProjectRules,
  ...telemetryProjectRules,
  ...structureProjectRules
];

/**
 * Rules that need files from every project in the run at once. Reachability is the only
 * analysis here that cannot be answered inside one project boundary.
 */
export const crossProjectRules = [...taintCrossProjectRules];

/** Findings sourced from an external auditor rather than from scanning source. */
export const externalRules = [VULNERABLE_DEPENDENCY_RULE];

export const allRules = [...fileRules, ...projectRules, ...crossProjectRules, ...externalRules];

export function ruleById(id) {
  return allRules.find((rule) => rule.id === id) || null;
}

/**
 * Decide which rules apply to a project. Rules excluded because the project lacks the
 * relevant capability are returned separately so the report can say so out loud — a scan
 * that quietly skipped the database rules is not the same as a scan that found nothing.
 */
export function selectRules(rules, { capabilities, only, skip }) {
  const active = [];
  const gated = [];
  for (const rule of rules) {
    if (only.length && !only.some((prefix) => rule.id === prefix || rule.id.startsWith(`${prefix}/`) || rule.category === prefix)) continue;
    if (skip.some((prefix) => rule.id === prefix || rule.id.startsWith(`${prefix}/`) || rule.category === prefix)) continue;
    if (rule.requires && !capabilities[rule.requires]) {
      gated.push({ rule, reason: rule.requires });
      continue;
    }
    active.push(rule);
  }
  return { active, gated };
}

export function rulesForLanguage(rules, language) {
  return rules.filter((rule) => rule.languages === "*" || (rule.languages || []).includes(language));
}

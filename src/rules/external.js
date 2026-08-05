import { VULNERABLE_DEPENDENCY_RULE } from "../audit.js";

/**
 * Rules for findings that came from another engine.
 *
 * An external finding is still a finding: it needs a category so it can be scored, a
 * rationale so `explain` has something to print, and a definition of done so it can become
 * a task in the fix plan. What it does not get is a pretence of local authorship — every
 * one of these carries the engine that produced it and that engine's own rule id, so a
 * developer arguing with a finding can go read the rule that raised it.
 *
 * They are grouped by domain rather than one-per-external-rule because the alternative is
 * a rule set that changes shape depending on which binaries happen to be installed. The
 * per-engine rule id lives on the finding; the Tripwire rule is the category it belongs to.
 */

export const EXTERNAL_RULES = {
  code: {
    id: "external/code-analysis",
    category: "security",
    severity: "high",
    title: "Weakness reported by a code analysis engine",
    why: "A dedicated SAST engine follows values across functions and files, which Tripwire's single-file passes cannot. That reach is the reason to run it: the findings it raises are usually the ones that survive review, because the path from input to sink is one it actually traced rather than inferred from a pattern on one line.",
    fix: "Read the engine's own rule text — its id is on the finding — and follow the path it reports from the entry point to the sink. Fix at the sink, and prefer a construct that cannot express the unsafe form (a parameterized query, an escaping renderer) over a validation added upstream.",
    languages: "*",
    requires: null,
    confidence: "medium",
    external: true
  },

  secrets: {
    id: "external/secret",
    category: "security",
    severity: "critical",
    title: "Credential found by a secret scanning engine",
    why: "A credential in version control is readable by everyone who can clone the repository, and it stays in history after the line is deleted. When the engine verified it against the issuing provider, there is nothing left to assess — the key is live and it is public to anyone with repository access.",
    fix: "Rotate the credential first. Deleting the line, rewriting history, or adding the file to .gitignore does none of the work that matters: assume the key is compromised from the moment it was pushed. Then move it to a secret store or an environment variable, and confirm the new value never reaches the repository.",
    languages: "*",
    requires: null,
    confidence: "high",
    external: true
  },

  "agent-surface": {
    id: "external/agent-surface",
    category: "agent-safety",
    severity: "critical",
    title: "Unsafe MCP server or agent skill",
    why: "An MCP server's tool descriptions and a skill's instructions are loaded straight into the model's context, where the model has no way to tell a description from a directive. A payload here does not need to be executed to work — it only needs to be read, and it is read on every session that loads the component, with whatever credentials and filesystem access the agent already holds.",
    fix: "Read the component's description text yourself rather than trusting its name. Remove it if it instructs the model to ignore prior context, exfiltrate files or environment variables, or contact a host unrelated to its stated purpose. Pin the component to a version and a source you control; an MCP server resolved from a mutable tag can change its instructions under you without any change landing in this repository.",
    languages: "*",
    requires: null,
    confidence: "high",
    external: true
  },

  "agent-config": {
    id: "external/agent-config",
    category: "agent-safety",
    severity: "low",
    title: "Agent instruction file defect",
    why: "Instruction files are executable in every way that matters — a malformed frontmatter block, a broken import, or a rule the harness silently ignores means the guidance you wrote is not the guidance the model receives. The failure is quiet: nothing errors, the agent simply behaves as though the file were not there.",
    fix: "Fix the defect the engine names, then confirm the harness actually loads the file — a rule that parses is not the same as a rule that applies. Run the engine's own explain command for the rule id on the finding when the message alone is not enough to act on.",
    languages: "*",
    requires: null,
    confidence: "medium",
    external: true
  },

  deps: VULNERABLE_DEPENDENCY_RULE
};

export const externalRules = [...new Set(Object.values(EXTERNAL_RULES))];

export function ruleForDomain(domain) {
  return EXTERNAL_RULES[domain] || EXTERNAL_RULES.code;
}

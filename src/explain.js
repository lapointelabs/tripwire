import { acceptanceCriteria } from "./report/fixplan.js";
import { allRules, CATEGORIES } from "./rules/index.js";

/**
 * The shapes each rule is known to get wrong.
 *
 * Publishing these is the point. An agent asked to "fix everything" will change correct
 * code unless it is told, concretely, what a false positive looks like for the rule in
 * front of it — and a tool that never admits its failure modes trains people to either
 * trust it blindly or stop reading it.
 */
const FALSE_POSITIVES = {
  "injection/sql-interpolation": [
    "A tagged template from a driver that parameterizes its interpolations (`sql`, `$queryRaw`, `Prisma.sql`). Tripwire skips the tags it knows; a project-local wrapper with a different name will still be flagged.",
    "SQL assembled entirely from constants defined in the same module, where the interpolated value cannot vary at runtime.",
    "A migration or seed script whose inputs come from the repository rather than from a caller."
  ],
  "injection/command-execution": [
    "A command built from values the program itself computed — a resolved path, a fixed flag — with no external input on the path.",
    "Developer tooling that is never exposed to untrusted input, though the habit is still worth breaking."
  ],
  "injection/dynamic-code-execution": [
    "`eval` in a test that is deliberately exercising evaluation behaviour.",
    "`yaml.load` where the loader is passed positionally rather than as a keyword, which the pattern cannot see."
  ],
  "injection/path-traversal": [
    "A containment check that happens in a helper function rather than inline — Tripwire looks for the check near the call and will miss one that is one level up the stack.",
    "A path whose dynamic segment is an identifier already validated against an allow-list earlier in the request."
  ],
  "web/raw-html-sink": [
    "Markup sanitized by a wrapper whose name Tripwire does not recognize as sanitization.",
    "A constant HTML string assigned from a module-level template with no interpolation."
  ],
  "web/missing-authorization-check": [
    "Authorization applied by router-level middleware registered elsewhere, which is invisible from the handler. This rule is low confidence for exactly this reason.",
    "An endpoint that is genuinely public by design."
  ],
  "web/insecure-randomness": [
    "A value named like a token that is only ever used for cache-busting, jitter, or a display identifier."
  ],
  "secrets/committed-credential": [
    "A key-shaped string in a test fixture or documentation example. Tripwire downgrades confidence inside test and fixture paths but cannot always tell.",
    "A public, non-secret identifier that happens to match a vendor prefix — a publishable key, for instance."
  ],
  "llm/untrusted-input-in-prompt": [
    "Content that is genuinely first-party — a constant, or text the application authored — that merely reads like user data.",
    "A prompt whose delimiting and 'treat as data' instruction live in a system prompt in a different file, which Tripwire cannot correlate."
  ],
  "llm/model-output-to-sink": [
    "Model output that is parsed and validated against a schema between the call and the sink, where the validation happens in a helper Tripwire cannot follow.",
    "A sink that only receives a field the model chose from a fixed enum."
  ],
  "llm/dynamic-tool-description": [
    "A description assembled at module load from constants, which is effectively static even though it is not a literal."
  ],
  "context/contradicted-comment": [
    "A comment describing intended behaviour that the code implements indirectly — through a helper, a base class, or a framework hook.",
    "A doc block covering an overload or a re-export rather than the function immediately beneath it."
  ],
  "context/stale-doc-parameter": [
    "A doc block documenting the members of a destructured options object. Tripwire skips destructured signatures, but a partially destructured one can still trip it."
  ],
  "context/stale-instruction-reference": [
    "A path that is generated at build time and genuinely does not exist in the repository.",
    "A backticked string that is a package name or a command fragment rather than a path."
  ],
  "context/commented-out-code": [
    "Commented example usage that is deliberately illustrative — though it usually belongs in a doc block or a test."
  ],
  "structure/await-in-loop": [
    "A loop where each iteration genuinely depends on the previous result, which is the correct use of sequential awaits.",
    "Deliberate rate limiting, where running the calls concurrently would exceed a quota.",
    "A loop over a handful of items where the latency does not matter."
  ],
  "structure/linear-lookup-in-loop": [
    "A collection small enough or fixed enough that the scan is cheaper than building a Set."
  ],
  "structure/unused-export": [
    "A symbol consumed by a different package in the same workspace, since Tripwire resolves imports per project.",
    "A public API export of a library, which exists to be imported by consumers outside the repository.",
    "A symbol resolved dynamically through a registry or dependency-injection container."
  ],
  "structure/silenced-error": [
    "A catch that is genuinely best-effort and documented as such in wording Tripwire does not recognize."
  ],
  "supply-chain/no-lockfile": [
    "A library whose lockfile is deliberately not committed so consumers resolve their own tree. The reproducibility cost is real; the decision may still be right.",
    "A fixture or example package that is never installed."
  ],
  "supply-chain/install-scripts-unrestricted": [
    "A policy declared somewhere Tripwire does not read — a global .npmrc, a CI flag, or an organisation-level setting rather than the project."
  ],
  "supply-chain/unpinned-ci-action": [
    "An action published from the same organisation, governed by the same review process as the code it builds.",
    "A workflow that handles no secrets and produces no artifact, where a compromised action gains nothing."
  ],
  "supply-chain/nuget-dependency-confusion": [
    "Feeds that are all internal mirrors of one another, where no name is resolvable from an untrusted source."
  ],
  "supply-chain/python-unpinned-requirements": [
    "An input file intended to be loose, with the pinned output compiled elsewhere. Tripwire reads requirements.txt as the installed set and cannot tell which role it plays."
  ],
  "supply-chain/mutable-dependency-reference": [
    "A reference to a repository you control, where a moved tag is your own change rather than a third party’."
  ],
  "taint/request-reaches-execution-sink": [
    "A method name that collides across files, since the join resolves a receiver by file name and a bare call by method name rather than by type. Check that the file named in the message is the one actually called.",
    "A value validated between the entry point and the sink — by a helper, an attribute, or a framework filter — which a one-hop join does not follow.",
    "An internal endpoint behind authentication and network policy. The chain is still real; the exposure is narrower."
  ],
  "telemetry/default-pii-enabled": [
    "A send hook elsewhere in the project that strips the payload before it leaves. Tripwire only looks in the same file, so a hook registered in a shared bootstrap module will be missed.",
    "A local-only or development configuration that never runs in an environment holding real data."
  ],
  "telemetry/user-identity-attached": [
    "A field named like personal data that holds an opaque value — a \`username\` that is a generated handle, or an \`email\` already hashed upstream."
  ],
  "telemetry/full-trace-sampling": [
    "A low-traffic internal service where complete traces are a deliberate, documented choice.",
    "Sampling gated by a helper function rather than an inline branch, which Tripwire cannot follow."
  ],
  "telemetry/scrubbed-from-logs-only": [
    "A telemetry send hook registered in a different file. This rule reasons about one file at a time, which is why it reports at low confidence."
  ],
  "auth/credential-in-query-string": [
    "A protocol that genuinely requires it — browser WebSocket clients cannot set an Authorization header — where the token is already single-use and short-lived. The exposure is real regardless; the question is whether every sink that records URLs strips it.",
    "A parameter named like a credential that carries an opaque, non-authenticating identifier."
  ],
  "config/hardcoded-overrides-config": [
    "A property name that coincidentally matches an unrelated configuration key, since matching is on the leaf name rather than the full binding path.",
    "A deliberate override for a value the configuration file only documents as a default."
  ],
  "structure/monolith-file": [
    "A generated file, a vendored dependency, or a data table, none of which are read the way source is."
  ]
};

export function findRule(id) {
  const exact = allRules.find((rule) => rule.id === id);
  if (exact) return { rule: exact, matches: [exact] };
  const partial = allRules.filter((rule) => rule.id.includes(id) || rule.title.toLowerCase().includes(id.toLowerCase()));
  return { rule: partial.length === 1 ? partial[0] : null, matches: partial };
}

/** Everything known about one rule, rendered for a terminal or an agent to read. */
export function explainRule(rule, palette) {
  const out = [];
  const criteria = acceptanceCriteria(
    { ruleId: rule.id, file: "this location", line: 0 },
    { why: rule.why, fix: rule.fix }
  );

  out.push("");
  out.push(`  ${palette.bold(rule.title)}`);
  out.push(`  ${palette.dim(`${rule.id} · ${rule.severity} · ${CATEGORIES[rule.category]?.label || rule.category}`)}`);
  out.push("");
  out.push(section(palette, "Why it matters", rule.why));
  out.push(section(palette, "How to fix it", rule.fix));

  out.push(`  ${palette.cyan("Done when")}`);
  for (const criterion of criteria) out.push(`    ${palette.dim("-")} ${wrap(stripMarkdown(criterion), 88, "      ")}`);
  out.push("");

  const falsePositives = FALSE_POSITIVES[rule.id];
  if (falsePositives) {
    out.push(`  ${palette.cyan("Known false positives")}`);
    for (const note of falsePositives) out.push(`    ${palette.dim("-")} ${wrap(stripMarkdown(note), 88, "      ")}`);
    out.push("");
  }

  const scope = [
    `Applies to: ${rule.languages === "*" ? "every language" : Array.isArray(rule.languages) ? rule.languages.join(", ") : "whole-project analysis"}`,
    rule.requires ? `Gated on: the project using ${rule.requires}` : null,
    `Baseline confidence: ${rule.confidence}${rule.aiTriage ? " — sent for model triage when a provider is configured" : ""}`
  ].filter(Boolean);
  for (const line of scope) out.push(`  ${palette.dim(line)}`);
  out.push("");
  return out.join("\n");
}

function section(palette, heading, text) {
  return `  ${palette.cyan(heading)}\n    ${wrap(stripMarkdown(text), 88, "    ")}\n`;
}

function stripMarkdown(text) {
  return String(text).replace(/\*\*/g, "").replace(/`/g, "");
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

/**
 * Reading SARIF 2.1.0 from another tool.
 *
 * Enough of the engines Tripwire delegates to already speak SARIF — Semgrep, Opengrep,
 * Snyk Code, agnix — that one reader covers most of the integration surface. It is also
 * the format least likely to move under us: a vendor's bespoke JSON is an implementation
 * detail they change at will, while SARIF is a spec they advertise conformance to.
 *
 * The awkward part of SARIF is that severity lives in three places and none of them are
 * required: `result.level`, the rule's `defaultConfiguration.level`, and a
 * `security-severity` property holding a CVSS-style number. Tools disagree about which to
 * populate, so all three are consulted in the order that loses the least information.
 */

/** SARIF levels are coarser than Tripwire's four, so the numeric score wins when present. */
const LEVEL_SEVERITY = { error: "high", warning: "medium", note: "low", none: "low" };

function severityFromScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

const PRECISION_CONFIDENCE = { "very-high": "high", high: "high", medium: "medium", low: "low" };

/**
 * A tool's own confidence in its finding, which SARIF has no standard field for.
 *
 * This matters more than it looks. Semgrep marks most of its rules `LOW CONFIDENCE` while
 * still emitting them at `error` level — `detect-child-process` fires on any `exec` call
 * reachable from a request, which is a lead, not a conclusion. Reading only the level
 * would push every one of those into the report as settled fact; reading the confidence
 * routes them to the triage layer instead, which is the entire reason that layer exists.
 *
 * Three places to look, because tools disagree about where to put it:
 *   - a `confidence` property, which the spec does not define but some tools emit
 *   - a `LOW/MEDIUM/HIGH CONFIDENCE` entry in the tag list, which is Semgrep's convention
 *   - a `precision` property, Semgrep's older signal for the same thing
 */
function confidenceFrom(properties = {}, severity) {
  const declared = String(properties.confidence || properties.Confidence || "").toLowerCase();
  if (declared === "high" || declared === "medium" || declared === "low") return declared;

  const tags = Array.isArray(properties.tags) ? properties.tags : [];
  const tagged = tags.find((tag) => /\b(LOW|MEDIUM|HIGH)\s+CONFIDENCE\b/i.test(String(tag)));
  if (tagged) return String(tagged).match(/\b(LOW|MEDIUM|HIGH)\s+CONFIDENCE\b/i)[1].toLowerCase();

  const precision = PRECISION_CONFIDENCE[String(properties.precision || "").toLowerCase()];
  if (precision) return precision;

  // Absent any declaration, treat the tool's own top severity as its confident tier and
  // everything below it as worth a second look.
  return severity === "critical" ? "high" : "medium";
}

/**
 * A usable short title.
 *
 * Semgrep sets `shortDescription` to the literal string `"Semgrep Finding: <rule id>"`,
 * which is the rule id twice over and tells a reader nothing. Where the short description
 * is that kind of echo, the first sentence of the real description is the better title.
 */
function titleFrom(rule, message, ruleId) {
  const short = textOf(rule?.shortDescription).trim();
  const echo = !short || /^semgrep finding:/i.test(short) || short === ruleId;
  if (!echo) return short;

  const body = textOf(rule?.fullDescription).trim() || message || "";
  // Trailing marketing lines ("Enable cross-file analysis…") are not part of the finding.
  const sentence = body.split(/(?<=[.!?])\s|\n/)[0].trim();
  return sentence.slice(0, 120) || ruleId || "External finding";
}

function textOf(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  return value.text || value.markdown || "";
}

/**
 * SARIF messages can be templates: `"{0} is used before {1}"` plus an argument array.
 * A report that prints the template with the placeholders still in it looks broken, so
 * substitute them.
 */
function renderMessage(message) {
  const text = textOf(message);
  const args = message?.arguments;
  if (!text || !Array.isArray(args) || !args.length) return text;
  return text.replace(/\{(\d+)\}/g, (match, index) => (args[index] === undefined ? match : String(args[index])));
}

function collectRules(run) {
  const rules = new Map();
  const driver = run?.tool?.driver;
  for (const extension of [driver, ...(run?.tool?.extensions || [])]) {
    for (const rule of extension?.rules || []) {
      if (rule?.id) rules.set(rule.id, rule);
    }
  }
  return rules;
}

/**
 * Turn one SARIF document into engine findings.
 *
 * `toRelative` maps a SARIF artifact URI onto a repository-relative path, and returns null
 * for anything outside the tree — a result about a file in the tool's own cache is not a
 * finding about this repository, and reporting it at a path nobody can open is worse than
 * dropping it.
 */
export function findingsFromSarif(document, { toRelative, defaultSeverity = "medium", engine }) {
  const findings = [];
  for (const run of document?.runs || []) {
    const rules = collectRules(run);

    for (const result of run.results || []) {
      // A suppression the tool itself honoured is not ours to re-litigate.
      if ((result.suppressions || []).some((entry) => entry?.status !== "rejected")) continue;

      const rule = rules.get(result.ruleId) || (Number.isInteger(result.ruleIndex)
        ? (run.tool?.driver?.rules || [])[result.ruleIndex]
        : null);
      const properties = { ...(rule?.properties || {}), ...(result.properties || {}) };

      const severity = severityFromScore(properties["security-severity"])
        || LEVEL_SEVERITY[result.level]
        || LEVEL_SEVERITY[rule?.defaultConfiguration?.level]
        || defaultSeverity;

      const location = (result.locations || [])[0]?.physicalLocation;
      const uri = location?.artifactLocation?.uri;
      const file = toRelative(uri);
      if (!file) continue;

      const region = location?.region || {};
      const line = Number(region.startLine) || 1;

      const externalRuleId = result.ruleId || rule?.id || "unknown";
      const message = renderMessage(result.message) || textOf(rule?.fullDescription) || externalRuleId;

      findings.push({
        engine,
        externalRuleId,
        file,
        line,
        endLine: Math.max(line, Number(region.endLine) || line),
        severity,
        confidence: confidenceFrom(properties, severity),
        title: titleFrom(rule, message, externalRuleId),
        message,
        evidence: textOf(region.snippet).split("\n")[0].trim().slice(0, 200),
        help: textOf(rule?.help),
        refs: [rule?.helpUri, ...(properties.references || [])].filter(Boolean).slice(0, 3),
        tags: properties.tags || []
      });
    }
  }
  return findings;
}

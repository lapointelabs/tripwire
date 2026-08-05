import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test, { describe } from "node:test";
import { fileURLToPath } from "node:url";
import { resolveSelection, unknownEngines } from "../src/config.js";
import { firstLine, parseJson, parseNdjson } from "../src/exec.js";
import { engineById, reconcile, relativizer, runEngine, uncoveredDomains } from "../src/engines/index.js";
import { findingsFromSarif } from "../src/engines/sarif.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const toRelative = relativizer("/repo");
const context = { toRelative, manifest: "package.json" };

function parse(id, payload, extra = {}) {
  return engineById(id).parse(payload, { ...context, ...extra });
}

describe("SARIF ingest", () => {
  /**
   * The fixture is a real capture from Semgrep 1.136.0, not a hand-written approximation.
   * Every field this adapter reads is one a hand-written fixture got wrong the first time:
   * `result.level` is absent, there is no `security-severity`, confidence hides in the tag
   * list, and `shortDescription` is the rule id echoed back with a prefix.
   */
  test("reads a real semgrep capture", async () => {
    const document = JSON.parse(await readFile(path.join(here, "fixtures/engines/semgrep.sarif.json"), "utf8"));
    const findings = findingsFromSarif(document, { toRelative, engine: "semgrep" });

    assert.equal(findings.length, 1);
    const [finding] = findings;
    assert.equal(finding.file, "app.js");
    assert.equal(finding.line, 6);
    assert.equal(finding.externalRuleId, "javascript.lang.security.detect-child-process.detect-child-process");
    // The rule carries defaultConfiguration.level "error" and no result-level override.
    assert.equal(finding.severity, "high");
    // "LOW CONFIDENCE" sits in properties.tags — the field the first version of this
    // adapter never looked at, so every semgrep finding came back "medium".
    assert.equal(finding.confidence, "low");
    assert.match(finding.message, /child_process/);
    assert.ok(!finding.title.startsWith("Semgrep Finding:"), `title still echoes the rule id: ${finding.title}`);
  });

  test("prefers a numeric security-severity over the level", () => {
    const findings = findingsFromSarif({
      runs: [{
        tool: { driver: { rules: [{ id: "r", properties: { "security-severity": "9.3" } }] } },
        results: [{ ruleId: "r", level: "note", message: { text: "m" }, locations: [location("a.js", 3)] }]
      }]
    }, { toRelative, engine: "e" });
    assert.equal(findings[0].severity, "critical");
  });

  test("falls back through result level then rule default", () => {
    const document = (result, rule) => ({
      runs: [{ tool: { driver: { rules: [{ id: "r", ...rule }] } }, results: [{ ruleId: "r", ...result, message: { text: "m" }, locations: [location("a.js", 1)] }] }]
    });
    assert.equal(findingsFromSarif(document({ level: "warning" }, {}), { toRelative, engine: "e" })[0].severity, "medium");
    assert.equal(findingsFromSarif(document({}, { defaultConfiguration: { level: "note" } }), { toRelative, engine: "e" })[0].severity, "low");
    assert.equal(findingsFromSarif(document({}, {}), { toRelative, engine: "e", defaultSeverity: "low" })[0].severity, "low");
  });

  test("reads confidence from a precision property when no tag says so", () => {
    const findings = findingsFromSarif({
      runs: [{
        tool: { driver: { rules: [{ id: "r", properties: { precision: "very-high" } }] } },
        results: [{ ruleId: "r", message: { text: "m" }, locations: [location("a.js", 1)] }]
      }]
    }, { toRelative, engine: "e" });
    assert.equal(findings[0].confidence, "high");
  });

  test("substitutes message template arguments", () => {
    const findings = findingsFromSarif({
      runs: [{
        tool: { driver: { rules: [{ id: "r" }] } },
        results: [{ ruleId: "r", message: { text: "{0} flows into {1}", arguments: ["req.query.id", "exec"] }, locations: [location("a.js", 1)] }]
      }]
    }, { toRelative, engine: "e" });
    // A report printing "{0} flows into {1}" reads as a broken tool.
    assert.equal(findings[0].message, "req.query.id flows into exec");
  });

  test("drops results outside the repository and honours the tool's own suppressions", () => {
    const findings = findingsFromSarif({
      runs: [{
        tool: { driver: { rules: [{ id: "r" }] } },
        results: [
          { ruleId: "r", message: { text: "outside" }, locations: [location("/etc/passwd", 1)] },
          { ruleId: "r", message: { text: "suppressed" }, locations: [location("a.js", 1)], suppressions: [{ kind: "inSource" }] },
          { ruleId: "r", message: { text: "kept" }, locations: [location("a.js", 2)] }
        ]
      }]
    }, { toRelative, engine: "e" });
    assert.deepEqual(findings.map((finding) => finding.message), ["kept"]);
  });
});

describe("trufflehog", () => {
  const entry = (overrides) => ({
    SourceMetadata: { Data: { Filesystem: { file: "/repo/src/config.js", line: 12 } } },
    DetectorName: "AWS",
    Redacted: "AKIA****************",
    ...overrides
  });

  test("treats a verified credential as critical and certain", () => {
    const [finding] = parse("trufflehog", [entry({ Verified: true })]);
    assert.equal(finding.severity, "critical");
    assert.equal(finding.confidence, "high");
    assert.equal(finding.verified, true);
    assert.match(finding.message, /rotate it/i);
  });

  test("keeps an unverified credential a lead, not a conclusion", () => {
    const [finding] = parse("trufflehog", [entry({ Verified: false, VerificationError: "connection refused" })]);
    assert.equal(finding.severity, "high");
    assert.equal(finding.confidence, "medium");
    assert.match(finding.message, /connection refused/);
  });

  test("never puts the raw secret in the evidence", () => {
    const [finding] = parse("trufflehog", [entry({ Verified: true, Raw: "AKIAIOSFODNN7EXAMPLE", RawV2: "AKIAIOSFODNN7EXAMPLE" })]);
    // Evidence reaches CI logs and the fix plan. Echoing the value there leaks it twice.
    assert.doesNotMatch(finding.evidence, /AKIAIOSFODNN7EXAMPLE/);
    assert.doesNotMatch(finding.message, /AKIAIOSFODNN7EXAMPLE/);
  });

  test("clamps a line of 0 to 1", () => {
    const [finding] = parse("trufflehog", [{
      SourceMetadata: { Data: { Filesystem: { file: "/repo/a.env", line: 0 } } },
      DetectorName: "Generic"
    }]);
    // Line 0 renders as a broken link in every editor and CI annotation that reads it.
    assert.equal(finding.line, 1);
  });

  test("ignores entries for files outside the repository", () => {
    const findings = parse("trufflehog", [{
      SourceMetadata: { Data: { Filesystem: { file: "/somewhere/else/.env", line: 3 } } },
      DetectorName: "AWS"
    }]);
    assert.equal(findings.length, 0);
  });
});

describe("gitleaks", () => {
  test("reads a report entry and stays medium confidence", () => {
    const [finding] = parse("gitleaks", [{
      Description: "AWS Access Key", File: "/repo/src/a.js", StartLine: 4, EndLine: 4,
      Match: "AKIA****", RuleID: "aws-access-token", Entropy: 3.72
    }]);
    assert.equal(finding.file, "src/a.js");
    assert.equal(finding.line, 4);
    assert.equal(finding.externalRuleId, "gitleaks/aws-access-token");
    // No verification step exists, so entropy alone never buys high confidence.
    assert.equal(finding.confidence, "medium");
    assert.match(finding.message, /3\.7/);
  });
});

describe("osv-scanner", () => {
  const payload = {
    results: [{
      source: { path: "/repo/package-lock.json", type: "lockfile" },
      packages: [{
        package: { name: "lodash", version: "4.17.15", ecosystem: "npm" },
        vulnerabilities: [
          { id: "GHSA-p6mc-m468-83gg", aliases: ["CVE-2020-8203"], summary: "Prototype pollution" },
          { id: "GHSA-xxxx", database_specific: { severity: "LOW" }, summary: "Minor issue" }
        ],
        groups: [{ ids: ["GHSA-p6mc-m468-83gg"], max_severity: "7.4" }]
      }]
    }]
  };

  test("takes severity from the group's computed max when present", () => {
    const findings = parse("osv-scanner", payload);
    const primary = findings.find((finding) => finding.externalRuleId === "GHSA-p6mc-m468-83gg");
    assert.equal(primary.severity, "high");
    assert.equal(primary.file, "package-lock.json");
    assert.match(primary.message, /CVE-2020-8203/);
    assert.match(primary.message, /lodash@4\.17\.15/);
  });

  test("falls back to the database's own named severity", () => {
    const findings = parse("osv-scanner", payload);
    assert.equal(findings.find((finding) => finding.externalRuleId === "GHSA-xxxx").severity, "low");
  });

  test("an advisory is stated as fact, not triaged", () => {
    assert.ok(parse("osv-scanner", payload).every((finding) => finding.confidence === "high"));
  });
});

describe("snyk-agent-scan", () => {
  const payload = {
    "/repo/.mcp.json": {
      issues: [
        { code: "E004", message: "Tool description contains an instruction override" },
        { code: "W015", message: "Server has no pinned version" },
        { code: "X001", message: "Server failed to start" }
      ]
    }
  };

  test("separates error-tier findings from warnings", () => {
    const findings = parse("snyk-agent-scan", payload);
    const codes = Object.fromEntries(findings.map((finding) => [finding.externalRuleId, finding.severity]));
    assert.equal(codes["snyk-agent-scan/E004"], "critical");
    assert.equal(codes["snyk-agent-scan/W015"], "medium");
  });

  test("drops X-codes, which are the scanner's own failures", () => {
    // An MCP server that would not start is a fact about the scan, not about the repository.
    const findings = parse("snyk-agent-scan", payload);
    assert.ok(!findings.some((finding) => finding.externalRuleId.includes("X001")));
  });

  test("finds issues nested below the documented top level", () => {
    // The nested shape is only partly specified and has moved between releases.
    const findings = parse("snyk-agent-scan", {
      "/repo/.mcp.json": { servers: [{ entities: [{ issues: [{ code: "E001", message: "deep" }] }] }] }
    });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, "critical");
  });
});

describe("reconciling overlapping sources", () => {
  const external = (overrides) => ({
    ruleId: "external/code-analysis", file: "src/a.js", line: 6, confidence: "low",
    evidence: "exec(...)", source: { engine: "semgrep", label: "Semgrep / Opengrep", ruleId: "js.detect-child-process" },
    ...overrides
  });
  const native = (overrides) => ({
    ruleId: "injection/command-execution", file: "src/a.js", line: 6, confidence: "high", evidence: "exec(...)",
    ...overrides
  });

  test("keeps the native high-confidence finding and records who agreed", () => {
    const [finding] = reconcile([external(), native()]);
    assert.equal(finding.ruleId, "injection/command-execution");
    assert.deepEqual(finding.corroboratedBy, ["Semgrep / Opengrep"]);
    assert.equal(finding.duplicatesSuppressed, 1);
  });

  test("a verified credential outranks every other source", () => {
    const [finding] = reconcile([
      { ruleId: "secrets/committed-credential", file: ".env", line: 3, confidence: "high" },
      { ruleId: "external/secret", file: ".env", line: 3, confidence: "high", source: { engine: "trufflehog", label: "TruffleHog", verified: true } }
    ]);
    assert.equal(finding.source?.engine, "trufflehog");
    assert.deepEqual(finding.corroboratedBy, ["Tripwire"]);
  });

  test("secrets within a line or two of each other are the same secret", () => {
    const findings = reconcile([
      { ruleId: "external/secret", file: ".env", line: 3, confidence: "medium", source: { engine: "gitleaks", label: "Gitleaks" } },
      { ruleId: "external/secret", file: ".env", line: 4, confidence: "high", source: { engine: "trufflehog", label: "TruffleHog", verified: true } }
    ]);
    assert.equal(findings.length, 1);
  });

  test("agreement lifts a low-confidence finding but cannot manufacture certainty", () => {
    const [finding] = reconcile([
      external(),
      external({ line: 6, source: { engine: "snyk-code", label: "Snyk Code", ruleId: "js/cmdi" } })
    ]);
    // Two guesses agreeing is evidence, not proof. Low becomes medium and stops there.
    assert.equal(finding.confidence, "medium");
  });

  test("advisories are matched by package, since every one points at line 1", () => {
    const advisory = (engine) => ({
      ruleId: "supply-chain/vulnerable-dependency", file: "package.json", line: 1, confidence: "high",
      evidence: "lodash@4.17.15", source: engine ? { engine, label: engine } : undefined
    });
    assert.equal(reconcile([advisory(), advisory("osv-scanner")]).length, 1);
    // A different package at the same line is a different finding.
    assert.equal(reconcile([advisory(), { ...advisory("osv-scanner"), evidence: "axios@0.21.1" }]).length, 2);
  });

  test("leaves unrelated findings alone", () => {
    assert.equal(reconcile([native(), native({ file: "src/b.js" }), external({ line: 40 })]).length, 3);
  });
});

describe("coverage reporting", () => {
  test("names the domains no engine covered", () => {
    const uncovered = uncoveredDomains([{ domain: "code", ran: true }, { domain: "secrets", ran: false }]);
    const domains = uncovered.map((entry) => entry.domain);
    assert.ok(!domains.includes("code"));
    assert.ok(domains.includes("secrets"));
    // Every gap states what Tripwire's own coverage of it is, so the reader can judge it.
    assert.ok(uncovered.every((entry) => entry.native));
  });
});

describe("engine execution", () => {
  const fakeEngine = (overrides) => ({
    id: "fake", label: "Fake", domain: "code", scope: "project", timeoutMs: 20_000,
    parse: (payload) => payload.findings || [],
    ...overrides
  });

  /**
   * The regression that matters most in this layer.
   *
   * Semgrep, handed `--metrics=off` before its subcommand, exits 2 after printing a
   * complete, schema-valid SARIF document with zero results. Parsed on its own that is
   * indistinguishable from a clean scan — and reporting a malformed command as "0 findings"
   * is the worst failure a security tool can have.
   */
  test("a valid envelope with a bad exit and no findings is a failed attempt", async () => {
    const outcome = await runEngine({
      engine: fakeEngine({
        attempts: () => [
          { args: ["-e", "console.log(JSON.stringify({findings:[]})); process.exit(2)"], format: "json" },
          { args: ["-e", "console.log(JSON.stringify({findings:[{file:'a.js',line:1}]}))"], format: "json" }
        ]
      }),
      launcher: { command: process.execPath },
      options: {}
    }, { root: process.cwd(), projectDir: process.cwd() });

    assert.equal(outcome.ran, true);
    // It fell through to the second argument set rather than reporting the first as clean.
    assert.equal(outcome.findings.length, 1);
  });

  test("a bad exit with findings is trusted — scanners exit non-zero when they find things", async () => {
    const outcome = await runEngine({
      engine: fakeEngine({
        attempts: () => [{ args: ["-e", "console.log(JSON.stringify({findings:[{file:'a.js',line:1}]})); process.exit(1)"], format: "json" }]
      }),
      launcher: { command: process.execPath },
      options: {}
    }, { root: process.cwd(), projectDir: process.cwd() });

    assert.equal(outcome.ran, true);
    assert.equal(outcome.findings.length, 1);
  });

  test("a clean exit with no output is zero findings, not a failure", async () => {
    const outcome = await runEngine({
      engine: fakeEngine({ attempts: () => [{ args: ["-e", ""], format: "json" }] }),
      launcher: { command: process.execPath },
      options: {}
    }, { root: process.cwd(), projectDir: process.cwd() });

    assert.equal(outcome.ran, true);
    assert.equal(outcome.total, 0);
  });

  test("a missing binary is reported, never thrown", async () => {
    const outcome = await runEngine({
      engine: fakeEngine({ attempts: () => [{ args: [], format: "json" }] }),
      launcher: { command: "tripwire-no-such-binary" },
      options: {}
    }, { root: process.cwd(), projectDir: process.cwd() });

    assert.equal(outcome.ran, false);
    assert.match(outcome.reason, /not installed/);
  });

  test("a parser that throws does not take the scan down", async () => {
    const outcome = await runEngine({
      engine: fakeEngine({
        parse: () => { throw new Error("bad shape"); },
        attempts: () => [{ args: ["-e", "console.log('{}')"], format: "json" }]
      }),
      launcher: { command: process.execPath },
      options: {}
    }, { root: process.cwd(), projectDir: process.cwd() });

    assert.equal(outcome.ran, false);
    assert.match(outcome.reason, /bad shape/);
  });
});

describe("configuration", () => {
  test("resolves the selection shorthands", () => {
    assert.equal(resolveSelection(undefined, { scan: {} }), "none");
    assert.equal(resolveSelection(true, { scan: {} }), "auto");
    assert.equal(resolveSelection("all", { scan: {} }), "all");
    assert.equal(resolveSelection("none", { scan: {} }), "none");
    assert.deepEqual(resolveSelection("semgrep,trufflehog", { scan: {} }), ["semgrep", "trufflehog"]);
  });

  test("falls back to the config file when no flag was passed", () => {
    assert.deepEqual(resolveSelection(undefined, { scan: { engines: ["semgrep"] } }), ["semgrep"]);
  });

  test("reports a misspelled engine instead of silently running nothing", () => {
    assert.deepEqual(unknownEngines(["semgrep", "trufflhog"]), ["trufflhog"]);
    assert.deepEqual(unknownEngines("auto"), []);
  });
});

describe("output parsing", () => {
  test("reads NDJSON past interleaved log lines", () => {
    const values = parseNdjson('INFO starting\n{"a":1}\nnot json\n{"b":2}\n');
    assert.deepEqual(values, [{ a: 1 }, { b: 2 }]);
  });

  test("reads a JSON array preceded by a human line", () => {
    assert.deepEqual(parseJson('scanning...\n[{"a":1}]'), [{ a: 1 }]);
  });

  test("reports the first meaningful stderr line", () => {
    assert.equal(firstLine("\n\n  error: no such command\nmore\n"), "error: no such command");
  });
});

function location(uri, startLine) {
  return { physicalLocation: { artifactLocation: { uri }, region: { startLine } } };
}

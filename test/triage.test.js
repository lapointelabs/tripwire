import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";
import { resolveProvider, triageFindings } from "../src/ai.js";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function anthropicReply(body) {
  return {
    ok: true,
    async json() {
      return { stop_reason: "end_turn", content: [{ type: "text", text: body }] };
    }
  };
}

function makeFinding(overrides = {}) {
  return {
    id: overrides.id || "rule/x:a.js:1",
    ruleId: "injection/sql-interpolation",
    title: "SQL built by string interpolation",
    message: "test",
    file: "a.js",
    line: 1,
    endLine: 1,
    evidence: "query(sql)",
    confidence: "medium",
    aiTriage: true,
    verdict: null,
    ...overrides
  };
}

const resolved = resolveProvider({ provider: "anthropic", apiKey: "test-key" });

describe("provider resolution", () => {
  test("reports why it is unavailable rather than failing silently", () => {
    const result = resolveProvider({ provider: "anthropic", apiKey: null });
    const withoutEnv = process.env.ANTHROPIC_API_KEY ? { available: true } : result;
    if (!withoutEnv.available) {
      assert.match(result.reason, /ANTHROPIC_API_KEY/);
    }
  });

  test("rejects an unknown provider by name", () => {
    const result = resolveProvider({ provider: "nope" });
    assert.equal(result.available, false);
    assert.match(result.reason, /unknown provider/);
  });

  test("defaults to the provider's recommended model", () => {
    assert.equal(resolved.config.model, "claude-opus-5");
  });
});

describe("triage", () => {
  test("sends only uncertain findings and folds verdicts back in", async () => {
    const findings = [
      makeFinding({ id: "a", confidence: "high", aiTriage: false }),
      makeFinding({ id: "b", confidence: "medium" }),
      makeFinding({ id: "c", confidence: "low" })
    ];

    let sentBody;
    globalThis.fetch = async (url, init) => {
      sentBody = JSON.parse(init.body);
      return anthropicReply(JSON.stringify({
        verdicts: [
          { id: "b", real: true, confidence: "high", reason: "reaches the driver unescaped", fix: "bind it" },
          { id: "c", real: false, confidence: "high", reason: "value is a constant" }
        ]
      }));
    };

    const outcome = await triageFindings(findings, { resolved, readFile: async () => "line\nline\nline" });

    assert.equal(outcome.reviewed, 2);
    assert.equal(outcome.errors.length, 0);
    // The high-confidence finding must never have been sent.
    assert.ok(!sentBody.messages[0].content.includes("candidate a"));
    assert.ok(sentBody.messages[0].content.includes("candidate b"));

    assert.equal(findings[0].verdict, null, "certain findings are left untouched");
    assert.equal(findings[1].confidence, "high");
    assert.equal(findings[1].verdict.fix, "bind it");
    assert.equal(findings[2].confidence, "refuted");
    assert.equal(findings[2].verdict.real, false);
  });

  test("never sends sampling parameters, which current models reject", async () => {
    let sentBody;
    globalThis.fetch = async (url, init) => {
      sentBody = JSON.parse(init.body);
      return anthropicReply('{"verdicts":[]}');
    };
    await triageFindings([makeFinding()], { resolved, readFile: async () => "x" });
    assert.equal(sentBody.temperature, undefined);
    assert.equal(sentBody.top_p, undefined);
    assert.equal(sentBody.top_k, undefined);
    assert.equal(sentBody.model, "claude-opus-5");
  });

  test("parses JSON wrapped in a fenced block", async () => {
    const finding = makeFinding({ id: "z" });
    globalThis.fetch = async () => anthropicReply(
      'Here you go:\n```json\n{"verdicts":[{"id":"z","real":false,"confidence":"high","reason":"constant"}]}\n```'
    );
    const outcome = await triageFindings([finding], { resolved, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 1);
    assert.equal(finding.confidence, "refuted");
  });

  test("survives a malformed response without losing the scan", async () => {
    const finding = makeFinding({ id: "q" });
    globalThis.fetch = async () => anthropicReply("I cannot help with that.");
    const outcome = await triageFindings([finding], { resolved, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 0);
    assert.equal(outcome.errors.length, 1);
    assert.equal(finding.confidence, "medium", "the original finding must be preserved");
  });

  test("surfaces a model refusal as an error rather than a verdict", async () => {
    const finding = makeFinding({ id: "r" });
    globalThis.fetch = async () => ({
      ok: true,
      async json() {
        return { stop_reason: "refusal", stop_details: { category: "cyber" }, content: [] };
      }
    });
    const outcome = await triageFindings([finding], { resolved, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 0);
    assert.match(outcome.errors[0], /declined/);
  });

  test("respects the budget and reports what it skipped", async () => {
    const findings = Array.from({ length: 5 }, (unused, index) => makeFinding({ id: `f${index}` }));
    globalThis.fetch = async () => anthropicReply('{"verdicts":[]}');
    const outcome = await triageFindings(findings, {
      resolved, readFile: async () => "x", budget: 2
    });
    assert.equal(outcome.truncated, 3);
  });
});

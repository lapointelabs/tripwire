import assert from "node:assert/strict";
import fs from "node:fs";
import { describe, test } from "node:test";
import { resolveProvider, triageFindings } from "../src/ai.js";

/** A stand-in for the Anthropic SDK client, capturing what the provider sends. */
function anthropicClient(reply, capture = {}) {
  return {
    messages: {
      create: async (body) => {
        capture.body = body;
        if (typeof reply === "function") return reply(body);
        return { stop_reason: "end_turn", content: [{ type: "text", text: reply }] };
      }
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

describe("cursor provider", () => {
  const cursor = resolveProvider({ provider: "cursor", apiKey: "cursor_test" });

  /** Stand-in for @cursor/sdk: Agent.prompt(text, options) -> { status, result }. */
  function cursorClient(run, capture = {}) {
    return {
      Agent: {
        prompt: async (text, options) => {
          capture.text = text;
          capture.options = options;
          return run;
        }
      }
    };
  }

  test("sends a one-shot prompt and reads the run result", async () => {
    const finding = makeFinding({ id: "c1" });
    const capture = {};
    const client = cursorClient({
      status: "FINISHED",
      result: JSON.stringify({ verdicts: [{ id: "c1", real: true, confidence: "high", reason: "reaches the driver", fix: "bind it" }] })
    }, capture);

    const outcome = await triageFindings([finding], { resolved: cursor, client, readFile: async () => "x" });

    assert.equal(outcome.reviewed, 1);
    assert.equal(finding.verdict.fix, "bind it");
    assert.ok(capture.text.includes("candidate c1"));
    assert.equal(capture.options.apiKey, "cursor_test");
    assert.deepEqual(capture.options.model, { id: "composer-2.5" });
    // `local` would hand the agent the working directory. Triage only needs the excerpts
    // already in the prompt, so it must never be set.
    assert.equal(capture.options.local, undefined, "triage must not grant repository access");
  });

  test("treats a non-finished run as an error and keeps the finding", async () => {
    const finding = makeFinding({ id: "c2" });
    const client = cursorClient({ status: "ERROR", result: null });
    const outcome = await triageFindings([finding], { resolved: cursor, client, readFile: async () => "x" });

    assert.equal(outcome.reviewed, 0);
    assert.match(outcome.errors[0], /ERROR/);
    assert.equal(finding.confidence, "medium", "a failed run must not downgrade a finding");
  });

  test("uses larger batches and lower concurrency than a chat endpoint", () => {
    assert.ok(cursor.definition.batchSize > 6);
    assert.ok(cursor.definition.concurrency < 3);
  });

  test("is an optional peer, so its install is opt-in", () => {
    const manifest = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(manifest.dependencies["@cursor/sdk"], undefined);
    assert.equal(manifest.peerDependenciesMeta["@cursor/sdk"].optional, true);
  });
});

describe("triage", () => {
  test("sends only uncertain findings and folds verdicts back in", async () => {
    const findings = [
      makeFinding({ id: "a", confidence: "high", aiTriage: false }),
      makeFinding({ id: "b", confidence: "medium" }),
      makeFinding({ id: "c", confidence: "low" })
    ];
    const capture = {};
    const client = anthropicClient(JSON.stringify({
      verdicts: [
        { id: "b", real: true, confidence: "high", reason: "reaches the driver unescaped", fix: "bind it" },
        { id: "c", real: false, confidence: "high", reason: "value is a constant" }
      ]
    }), capture);

    const outcome = await triageFindings(findings, { resolved, client, readFile: async () => "line\nline\nline" });

    assert.equal(outcome.reviewed, 2);
    assert.equal(outcome.errors.length, 0);
    // The high-confidence finding must never have been sent.
    assert.ok(!capture.body.messages[0].content.includes("candidate a"));
    assert.ok(capture.body.messages[0].content.includes("candidate b"));

    assert.equal(findings[0].verdict, null, "certain findings are left untouched");
    assert.equal(findings[1].confidence, "high");
    assert.equal(findings[1].verdict.fix, "bind it");
    assert.equal(findings[2].confidence, "refuted");
    assert.equal(findings[2].verdict.real, false);
  });

  test("never sends sampling parameters, which current models reject", async () => {
    const capture = {};
    await triageFindings([makeFinding()], {
      resolved, client: anthropicClient(String.raw`{"verdicts":[]}`, capture), readFile: async () => "x"
    });
    assert.equal(capture.body.temperature, undefined);
    assert.equal(capture.body.top_p, undefined);
    assert.equal(capture.body.top_k, undefined);
    assert.equal(capture.body.model, "claude-opus-5");
  });

  test("parses JSON wrapped in a fenced block", async () => {
    const finding = makeFinding({ id: "z" });
    const client = anthropicClient(
      String.raw`Here you go:` + "\n```json\n" + String.raw`{"verdicts":[{"id":"z","real":false,"confidence":"high","reason":"constant"}]}` + "\n```"
    );
    const outcome = await triageFindings([finding], { resolved, client, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 1);
    assert.equal(finding.confidence, "refuted");
  });

  test("survives a malformed response without losing the scan", async () => {
    const finding = makeFinding({ id: "q" });
    const client = anthropicClient("I cannot help with that.");
    const outcome = await triageFindings([finding], { resolved, client, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 0);
    assert.equal(outcome.errors.length, 1);
    assert.equal(finding.confidence, "medium", "the original finding must be preserved");
  });

  test("surfaces a model refusal as an error rather than a verdict", async () => {
    const finding = makeFinding({ id: "r" });
    const client = anthropicClient(() => ({ stop_reason: "refusal", stop_details: { category: "cyber" }, content: [] }));
    const outcome = await triageFindings([finding], { resolved, client, readFile: async () => "x" });
    assert.equal(outcome.reviewed, 0);
    assert.match(outcome.errors[0], /declined/);
  });

  test("respects the budget and reports what it skipped", async () => {
    const findings = Array.from({ length: 5 }, (unused, index) => makeFinding({ id: `f${index}` }));
    const outcome = await triageFindings(findings, {
      resolved, client: anthropicClient(String.raw`{"verdicts":[]}`), readFile: async () => "x", budget: 2
    });
    assert.equal(outcome.truncated, 3);
  });
});

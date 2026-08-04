import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { detectProjects } from "../src/detect.js";
import { scanProject } from "../src/scan.js";
import { scoreProject } from "../src/score.js";
import { prepareFile } from "../src/source.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureRoot = path.join(root, "test", "fixtures", "vulnerable");

async function scanFixture() {
  const projects = await detectProjects(fixtureRoot);
  const project = projects.find((candidate) => candidate.relative === ".");
  assert.ok(project, "fixture project should be detected");
  return scanProject({ root: fixtureRoot, project });
}

function at(findings, ruleId, file, line) {
  return findings.some((finding) => finding.ruleId === ruleId
    && finding.file === file
    && finding.line === line);
}

describe("detection", () => {
  test("identifies the fixture stack and its capabilities", async () => {
    const [project] = await detectProjects(fixtureRoot);
    assert.equal(project.language, "JavaScript");
    assert.equal(project.framework, "Express");
    assert.ok(project.aiPackages.includes("@anthropic-ai/sdk"));
    assert.ok(project.dbPackages.includes("pg"));
  });

  test("finds every project in a nested tree", async () => {
    const projects = await detectProjects(path.join(root, "test", "fixtures"));
    assert.ok(projects.length >= 1);
    assert.ok(projects.every((project) => project.relative && project.language));
  });
});

describe("security rules", () => {
  test("flags each seeded vulnerability exactly where it lives", async () => {
    const { findings } = await scanFixture();
    const expected = [
      ["injection/sql-interpolation", "src/api.js", 11],
      ["injection/sql-interpolation", "src/api.js", 17],
      ["injection/command-execution", "src/api.js", 33],
      ["injection/path-traversal", "src/api.js", 38],
      ["injection/dynamic-code-execution", "src/api.js", 55],
      ["web/raw-html-sink", "src/api.js", 44],
      ["web/disabled-tls-verification", "src/api.js", 48],
      ["web/permissive-cors", "src/api.js", 51],
      ["secrets/committed-credential", "src/agent.js", 7]
    ];
    for (const [ruleId, file, line] of expected) {
      assert.ok(at(findings, ruleId, file, line), `expected ${ruleId} at ${file}:${line}`);
    }
  });

  test("does not flag the parameterized or tagged-template queries", async () => {
    const { findings } = await scanFixture();
    const sqlLines = findings
      .filter((finding) => finding.ruleId === "injection/sql-interpolation")
      .map((finding) => finding.line);
    // Lines 22 and 28 are the safe variants in the fixture.
    assert.ok(!sqlLines.includes(22), "parameterized query must not be flagged");
    assert.ok(!sqlLines.includes(28), "tagged template must not be flagged");
  });

  test("redacts the secret rather than reprinting it", async () => {
    const { findings } = await scanFixture();
    const secret = findings.find((finding) => finding.ruleId === "secrets/committed-credential");
    assert.ok(secret);
    assert.ok(!/sk-ant-api03-9fJ2/.test(secret.evidence), "evidence must not contain the full key");
    assert.match(secret.evidence, /\*{4,}/);
  });
});

describe("agent-safety rules", () => {
  test("flags prompt injection, sink flow, tool description, and permission bypass", async () => {
    const { findings } = await scanFixture();
    const expected = [
      ["llm/untrusted-input-in-prompt", "src/agent.js", 16],
      ["llm/model-output-to-sink", "src/agent.js", 38],
      ["llm/dynamic-tool-description", "src/agent.js", 45],
      ["llm/permission-bypass", "src/agent.js", 51]
    ];
    for (const [ruleId, file, line] of expected) {
      assert.ok(at(findings, ruleId, file, line), `expected ${ruleId} at ${file}:${line}`);
    }
  });

  test("does not flag a prompt that separates instructions from delimited data", async () => {
    const { findings } = await scanFixture();
    const promptLines = findings
      .filter((finding) => finding.ruleId === "llm/untrusted-input-in-prompt")
      .map((finding) => finding.line);
    assert.ok(!promptLines.some((line) => line > 20 && line < 30), "delimited prompt must not be flagged");
  });

  test("gates model rules off when the project has no model SDK", async () => {
    const project = {
      kind: "node", name: "plain", directory: fixtureRoot, relative: ".",
      language: "JavaScript", framework: "Node.js", manifest: "package.json",
      aiPackages: [], dbPackages: [], isWorkspaceRoot: false
    };
    const result = await scanProject({ root: fixtureRoot, project });
    assert.ok(result.gatedRules.some((rule) => rule.id === "llm/untrusted-input-in-prompt"));
    assert.ok(!result.findings.some((finding) => finding.ruleId === "llm/untrusted-input-in-prompt"));
  });
});

describe("lexer", () => {
  test("blanks comments and string bodies but keeps template expressions visible", () => {
    const source = [
      'const a = "SELECT * FROM users";',
      "// const b = dangerous();",
      "const c = `SELECT ${name}`;"
    ].join("\n");
    const file = prepareFile({ relative: "x.js", language: "javascript" }, source);
    assert.ok(!file.code.includes("SELECT"), "string bodies must be blanked");
    assert.ok(!file.code.includes("dangerous"), "comment bodies must be blanked");
    assert.ok(file.code.includes("${name}"), "template expressions are real code and must survive");
    assert.equal(file.code.length, source.length, "offsets must be preserved");
  });

  test("reports comments with their line numbers", () => {
    const file = prepareFile({ relative: "x.js", language: "javascript" }, "a();\n// note here\nb();");
    const comment = file.comments.find((entry) => entry.kind === "line");
    assert.equal(comment.line, 2);
    assert.equal(comment.text, "note here");
  });

  test("blanks regex literals but leaves division alone", () => {
    const source = [
      "const p = /SELECT .* FROM/i;",
      "const ratio = total / count / 2;"
    ].join("\n");
    const file = prepareFile({ relative: "x.js", language: "javascript" }, source);
    assert.ok(!file.code.includes("SELECT"), "regex bodies must be blanked");
    assert.ok(file.code.includes("total"), "division operands are code and must survive");
    assert.ok(file.code.includes("count"), "division must not be swallowed as a regex");
    assert.equal(file.code.length, source.length);
  });
});

describe("specification versus occurrence", () => {
  test("does not flag a pattern written to detect a vulnerability", async () => {
    const source = [
      "const RISKY = /dangerouslySkipPermissions|bypassPermissions/;",
      "// Detects permissionMode: \"bypassPermissions\" in agent configs.",
      "export { RISKY };"
    ].join("\n");
    const file = prepareFile({ relative: "detector.js", language: "javascript" }, source);
    const { llmRules } = await import("../src/rules/llm.js");
    const rule = llmRules.find((candidate) => candidate.id === "llm/permission-bypass");
    assert.deepEqual(rule.scan(file), [], "a detector must not report itself");
  });

  test("still flags the real thing", async () => {
    const file = prepareFile(
      { relative: "config.js", language: "javascript" },
      'export const options = { permissionMode: "bypassPermissions" };'
    );
    const { llmRules } = await import("../src/rules/llm.js");
    const rule = llmRules.find((candidate) => candidate.id === "llm/permission-bypass");
    assert.equal(rule.scan(file).length, 1);
  });

  test("does not flag SQL discussed in a comment", async () => {
    const source = [
      "// Never write: \"SELECT * FROM users WHERE id = \" + id",
      "export function safe(id) { return db.query('SELECT * FROM users WHERE id = $1', [id]); }"
    ].join("\n");
    const file = prepareFile({ relative: "db.js", language: "javascript" }, source);
    const { injectionRules } = await import("../src/rules/injection.js");
    const rule = injectionRules.find((candidate) => candidate.id === "injection/sql-interpolation");
    assert.deepEqual(rule.scan(file), []);
  });
});

describe("loop scope detection", () => {
  test("does not treat an await in a loop header as sequential", async () => {
    const source = [
      "async function run(dirs) {",
      "  for (const name of await readdir(root, { recursive: true })) {",
      "    use(name);",
      "  }",
      "}"
    ].join("\n");
    const file = prepareFile({ relative: "x.js", language: "javascript" }, source);
    const { structureRules } = await import("../src/rules/structure.js");
    const rule = structureRules.find((candidate) => candidate.id === "structure/await-in-loop");
    assert.deepEqual(rule.scan(file), []);
  });

  test("flags an await inside the loop body", async () => {
    const source = [
      "async function run(items) {",
      "  for (const item of items) {",
      "    await save(item);",
      "  }",
      "}"
    ].join("\n");
    const file = prepareFile({ relative: "x.js", language: "javascript" }, source);
    const { structureRules } = await import("../src/rules/structure.js");
    const rule = structureRules.find((candidate) => candidate.id === "structure/await-in-loop");
    const found = rule.scan(file);
    assert.equal(found.length, 1);
    assert.equal(found[0].line, 3);
  });
});

describe("scoring", () => {
  test("caps the score when a confirmed critical finding is present", async () => {
    const { findings, stats } = await scanFixture();
    const summary = scoreProject(findings, stats);
    assert.ok(summary.score <= 55, `expected a capped score, got ${summary.score}`);
    assert.ok(summary.bySeverity.critical > 0);
  });

  test("excludes findings the triage layer refuted", async () => {
    const stats = { lines: 1000 };
    const findings = [
      { severity: "critical", category: "security", confidence: "high", verdict: { real: false } },
      { severity: "low", category: "maintainability", confidence: "high" }
    ];
    const summary = scoreProject(findings, stats);
    assert.equal(summary.total, 1);
    assert.equal(summary.refuted, 1);
    assert.equal(summary.bySeverity.critical, 0);
  });

  test("scores a clean project at 100", () => {
    const summary = scoreProject([], { lines: 5000 });
    assert.equal(summary.score, 100);
    assert.equal(summary.grade, "Healthy");
  });
});

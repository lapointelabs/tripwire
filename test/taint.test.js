import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { detectProjects } from "../src/detect.js";
import { injectionRules } from "../src/rules/injection.js";
import { untrustedNames } from "../src/rules/helpers.js";
import { scanAcrossProjects, scanProject } from "../src/scan.js";
import { prepareFile } from "../src/source.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureRoot = path.join(root, "test", "fixtures", "taint");

async function scanFixture() {
  const projects = await detectProjects(fixtureRoot);
  const results = [];
  for (const project of projects) {
    results.push(await scanProject({ root: fixtureRoot, project }));
  }
  await scanAcrossProjects(results);
  return results;
}

describe("request-binding taint sources", () => {
  test("reads ASP.NET model binding attributes", () => {
    const file = prepareFile({ relative: "C.cs", language: "csharp" },
      "public async Task<IActionResult> Get([FromQuery] string host, [FromBody] Dto payload, CancellationToken ct)");
    const names = untrustedNames(file);
    assert.ok(names.has("host"));
    assert.ok(names.has("payload"));
    assert.ok(!names.has("ct"), "an unbound parameter is not attacker-controlled");
  });

  test("reads Node request destructuring", () => {
    const file = prepareFile({ relative: "r.js", language: "javascript" },
      "const { host, port } = req.query;\nconst body = request.body;");
    const names = untrustedNames(file);
    assert.ok(names.has("host"));
    assert.ok(names.has("port"));
    assert.ok(names.has("body"));
  });
});

describe("shell interpreter raises confidence", () => {
  const rule = injectionRules.find((candidate) => candidate.id === "injection/command-execution");

  test("names the interpreter and reports high confidence", () => {
    // `host` is a domain-shaped name, so a name-based heuristic alone rates this medium.
    // The explicit `cmd.exe` removes the ambiguity: that argument string is parsed by a shell.
    const file = prepareFile({ relative: "P.cs", language: "csharp" }, [
      "var info = new ProcessStartInfo {",
      '    FileName = "cmd.exe",',
      '    Arguments = $"/c ping -n 1 {host}",',
      "};"
    ].join("\n"));
    const found = rule.scan(file);
    assert.equal(found.length, 1);
    assert.equal(found[0].confidence, "high");
    assert.match(found[0].message, /cmd\.exe/);
  });

  test("still reports medium when no interpreter is named", () => {
    const file = prepareFile({ relative: "P.cs", language: "csharp" },
      'var info = new ProcessStartInfo { FileName = "printer-tool", Arguments = $"--host {host}" };');
    const found = rule.scan(file);
    assert.equal(found.length, 1);
    assert.equal(found[0].confidence, "medium");
  });
});

describe("cross-project reachability", () => {
  test("joins a controller in one project to a sink in another", async () => {
    const results = await scanFixture();
    const findings = results.flatMap((result) => result.findings)
      .filter((finding) => finding.ruleId === "taint/request-reaches-execution-sink");

    assert.equal(findings.length, 1, "the reachable chain should be reported exactly once");
    const [finding] = findings;
    assert.equal(finding.severity, "critical");
    assert.equal(finding.confidence, "high");

    // The message has to carry the whole chain: without the route and the sink location
    // this is indistinguishable from a sink someone can only reach from a cron job.
    assert.match(finding.message, /GET/);
    assert.match(finding.message, /host/);
    assert.match(finding.message, /ReachabilityChecker\.ProbeAsync/);
    assert.match(finding.message, /ReachabilityChecker\.cs:\d+/);
  });

  test("attributes the finding to the entry point, not the sink", async () => {
    const results = await scanFixture();
    const finding = results.flatMap((result) => result.findings)
      .find((candidate) => candidate.ruleId === "taint/request-reaches-execution-sink");
    // Reported where someone would go to fix it: the route that exposes the sink.
    assert.match(finding.file, /ProbeController\.cs$/);
  });

  test("does not flag a handler that passes a constant it chose itself", async () => {
    const results = await scanFixture();
    const findings = results.flatMap((result) => result.findings)
      .filter((finding) => finding.ruleId === "taint/request-reaches-execution-sink");
    assert.ok(!findings.some((finding) => /SelfTest/.test(finding.evidence || "")),
      "a hardcoded argument is not request-controlled");
  });

  test("finds nothing when the projects are scanned in isolation", async () => {
    // This is the failure the cross-project pass exists to fix: a layered solution puts
    // the controller and the helper in different assemblies, so a per-project join sees
    // one half of the chain and reports nothing.
    const projects = await detectProjects(fixtureRoot);
    for (const project of projects) {
      const result = await scanProject({ root: fixtureRoot, project });
      const taint = result.findings.filter((finding) => finding.ruleId === "taint/request-reaches-execution-sink");
      assert.deepEqual(taint, [], "per-project scanning cannot see the chain");
    }
  });
});

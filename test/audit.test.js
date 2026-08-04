import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { auditProject, fromCargoAudit, fromGovulncheck, parseJsonStream, VULNERABLE_DEPENDENCY_RULE } from "../src/audit.js";
import { allRules } from "../src/rules/index.js";

const scratch = [];
after(async () => {
  for (const directory of scratch) await rm(directory, { recursive: true, force: true });
});

async function workspace(files = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "tripwire-audit-"));
  scratch.push(root);
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, typeof contents === "string" ? contents : JSON.stringify(contents), "utf8");
  }
  return root;
}

function nodeProject(directory) {
  return { kind: "node", name: "demo", directory, relative: ".", manifest: "package.json" };
}

describe("audit integration", () => {
  test("is registered as a rule so the report can group and explain it", () => {
    assert.ok(allRules.some((rule) => rule.id === VULNERABLE_DEPENDENCY_RULE.id));
    assert.equal(VULNERABLE_DEPENDENCY_RULE.category, "supply-chain");
    assert.ok(VULNERABLE_DEPENDENCY_RULE.why && VULNERABLE_DEPENDENCY_RULE.fix);
  });

  test("reports why it could not run instead of throwing", async () => {
    // A python project with no pip-audit on PATH is the common case, and it must
    // degrade to a stated reason — the deterministic scan is the product.
    const root = await workspace({ "pyproject.toml": '[project]\nname = "svc"\n' });
    const result = await auditProject({ kind: "python", name: "svc", directory: root, relative: ".", manifest: "pyproject.toml" }, { root });
    assert.equal(result.ran, false);
    assert.ok(result.reason);
    assert.deepEqual(result.findings, []);
  });

  test("reports an unknown ecosystem rather than guessing a command", async () => {
    const root = await workspace({});
    const result = await auditProject({ kind: "ruby", name: "x", directory: root, relative: "." }, { root });
    assert.equal(result.ran, false);
    assert.match(result.reason, /no auditor/);
  });

  test("refuses to run an auditor whose prerequisite is missing", async () => {
    // `dotnet list package --vulnerable` needs a restore; without one it reports nothing
    // useful, and a silent empty result would read as "no vulnerabilities".
    const root = await workspace({ "App.csproj": "<Project />" });
    const result = await auditProject({ kind: "dotnet", name: "App", directory: root, relative: ".", manifest: "App.csproj" }, { root });
    assert.equal(result.ran, false);
    assert.match(result.reason, /restore/i);
  });

  test("runs npm audit and normalizes a real advisory", async (t) => {
    const root = await workspace({
      "package.json": { name: "vuln-demo", version: "1.0.0", private: true, dependencies: { minimist: "1.2.0" } }
    });

    // Generating the lockfile needs the registry; skip rather than fail when offline.
    const { spawnSync } = await import("node:child_process");
    const install = spawnSync("npm", ["install", "--package-lock-only", "--silent", "--no-audit", "--no-fund"], { cwd: root, encoding: "utf8" });
    if (install.status !== 0) return t.skip("registry unavailable");

    const result = await auditProject(nodeProject(root), { root });
    if (!result.ran) return t.skip(`npm audit unavailable: ${result.reason}`);

    assert.ok(result.findings.length >= 1, "a known-vulnerable version should produce a finding");
    const finding = result.findings[0];
    assert.equal(finding.confidence, "high", "an advisory is authoritative, not a pattern guess");
    assert.match(finding.evidence, /minimist/);
    assert.match(finding.message, /advisory/);
    assert.equal(finding.file, "package.json");
    assert.ok(["critical", "high", "medium", "low"].includes(finding.severity));
  });

  test("finds nothing to report for a clean tree", async (t) => {
    const root = await workspace({
      "package.json": { name: "clean", version: "1.0.0", private: true, dependencies: {} },
      "package-lock.json": { name: "clean", lockfileVersion: 3, requires: true, packages: { "": { name: "clean" } } }
    });
    const result = await auditProject(nodeProject(root), { root });
    if (!result.ran) return t.skip(`npm audit unavailable: ${result.reason}`);
    assert.equal(result.total, 0);
    assert.deepEqual(result.findings, []);
  });
});

describe("govulncheck", () => {
  // The real `-json` shape: a stream of concatenated, pretty-printed objects.
  const stream = `{
  "config": { "protocol_version": "v1.0.0", "scanner_name": "govulncheck" }
}
{
  "progress": { "message": "Scanning your code and 42 packages" }
}
{
  "osv": {
    "id": "GO-2024-2611",
    "aliases": ["CVE-2024-24783"],
    "summary": "Panic in crypto/x509 certificate parsing",
    "affected": [{ "package": { "name": "stdlib", "ecosystem": "Go" } }]
  }
}
{
  "osv": {
    "id": "GO-2023-1988",
    "summary": "Improper handling in golang.org/x/net",
    "affected": [{ "package": { "name": "golang.org/x/net", "ecosystem": "Go" } }]
  }
}
{
  "finding": {
    "osv": "GO-2024-2611",
    "fixed_version": "go1.22.1",
    "trace": [{ "module": "stdlib", "package": "crypto/x509", "function": "ParseCertificate" }]
  }
}
{
  "finding": {
    "osv": "GO-2023-1988",
    "fixed_version": "v0.17.0",
    "trace": [{ "module": "golang.org/x/net", "version": "v0.15.0" }]
  }
}`;

  test("splits concatenated JSON objects that are neither one document nor one per line", () => {
    const messages = parseJsonStream(stream);
    assert.equal(messages.length, 6);
    assert.equal(messages[0].config.scanner_name, "govulncheck");
    assert.equal(messages.filter((message) => message.osv).length, 2);
  });

  test("is not confused by braces inside strings", () => {
    const values = parseJsonStream('{"a":"} not the end {"}{"b":2}');
    assert.deepEqual(values, [{ a: "} not the end {" }, { b: 2 }]);
  });

  test("separates reachable vulnerabilities from merely imported ones", () => {
    const found = fromGovulncheck(parseJsonStream(stream));
    assert.equal(found.length, 2);

    // A trace naming a function means the vulnerable code is actually called; that
    // distinction is the reason to run govulncheck rather than diff a lockfile.
    const called = found.find((entry) => entry.package === "stdlib");
    assert.equal(called.severity, "high");
    assert.match(called.title, /Panic in crypto\/x509/);
    assert.match(called.fix, /go1\.22\.1/);

    const imported = found.find((entry) => entry.package === "golang.org/x/net");
    assert.equal(imported.severity, "low");
    assert.match(imported.title, /not reachable/);
  });

  test("points at the Go vulnerability database entry", () => {
    const [first] = fromGovulncheck(parseJsonStream(stream));
    assert.match(first.ids[0], /pkg\.go\.dev\/vuln\/GO-/);
  });
});

describe("cargo audit", () => {
  const payload = {
    vulnerabilities: {
      found: true,
      count: 1,
      list: [{
        advisory: { id: "RUSTSEC-2020-0071", package: "time", title: "Potential segfault in the time crate" },
        versions: { patched: [">=0.2.23"] },
        package: { name: "time", version: "0.1.44" }
      }]
    },
    warnings: {
      unmaintained: [{
        kind: "unmaintained",
        advisory: { id: "RUSTSEC-2021-0139", title: "ansi_term is Unmaintained" },
        versions: { patched: [] },
        package: { name: "ansi_term", version: "0.12.1" }
      }]
    }
  };

  test("reports advisories and informational warnings at different severities", () => {
    const found = fromCargoAudit(payload);
    assert.equal(found.length, 2);

    const vulnerability = found.find((entry) => entry.package === "time");
    assert.equal(vulnerability.severity, "high");
    assert.match(vulnerability.fix, />=0\.2\.23/);
    assert.match(vulnerability.ids[0], /rustsec\.org\/advisories\/RUSTSEC-2020-0071/);

    // Unmaintained is worth knowing and is not a vulnerability; rating them alike
    // would drown the real advisory in crates that simply stopped being updated.
    const warning = found.find((entry) => entry.package === "ansi_term");
    assert.equal(warning.severity, "low");
    assert.match(warning.title, /unmaintained/);
  });

  test("handles a clean audit", () => {
    assert.deepEqual(fromCargoAudit({ vulnerabilities: { found: false, count: 0, list: [] }, warnings: {} }), []);
  });
});

describe("Go and Rust prerequisites", () => {
  test("tells the user how to install a missing auditor", async () => {
    const root = await workspace({ "go.mod": "module example.com/x\n\ngo 1.22\n" });
    const result = await auditProject({ kind: "go", name: "x", directory: root, relative: ".", manifest: "go.mod" }, { root });
    if (result.ran) return;
    assert.match(result.reason, /govulncheck/);
    assert.match(result.reason, /go install golang\.org\/x\/vuln/);
  });

  test("requires a Cargo.lock before running cargo audit", async () => {
    const root = await workspace({ "Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n' });
    const result = await auditProject({ kind: "rust", name: "x", directory: root, relative: ".", manifest: "Cargo.toml" }, { root });
    assert.equal(result.ran, false);
    assert.match(result.reason, /Cargo\.lock/);
  });
});

describe("subcommand auditors", () => {
  test("gives an install hint when the binary exists but the subcommand does not", async () => {
    // `cargo` is usually installed while `cargo-audit` is not, so the failure surfaces as
    // "no such command" rather than a missing binary — the message must still be useful.
    const root = await workspace({
      "Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
      "Cargo.lock": "# generated\n"
    });
    const result = await auditProject({ kind: "rust", name: "x", directory: root, relative: ".", manifest: "Cargo.toml" }, { root });
    if (result.ran) return;
    assert.match(result.reason, /cargo install cargo-audit/);
  });
});

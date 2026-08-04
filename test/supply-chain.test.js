import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { detectProjects } from "../src/detect.js";
import { scanProject } from "../src/scan.js";

const scratch = [];
after(async () => {
  for (const directory of scratch) await rm(directory, { recursive: true, force: true });
});

/** Build a throwaway project from a map of relative path -> contents, then scan it. */
async function scan(files, { only } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "tripwire-sc-"));
  scratch.push(root);
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, typeof contents === "string" ? contents : JSON.stringify(contents, null, 2), "utf8");
  }
  const [project] = await detectProjects(root);
  if (!project) return [];
  const result = await scanProject({ root, project, only: only ? [only] : [] });
  return result.findings.filter((finding) => finding.category === "supply-chain");
}

function ids(findings) {
  return [...new Set(findings.map((finding) => finding.ruleId))].sort();
}

describe("lockfiles and version pinning", () => {
  test("flags dependencies with no lockfile", async () => {
    const findings = await scan({ "package.json": { name: "a", dependencies: { left: "^1.0.0" } } });
    assert.ok(ids(findings).includes("supply-chain/no-lockfile"));
  });

  test("does not flag when a lockfile is present", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "package-lock.json": { lockfileVersion: 3 }
    });
    assert.ok(!ids(findings).includes("supply-chain/no-lockfile"));
  });

  test("does not ask a dependency-free manifest for a lockfile", async () => {
    const findings = await scan({ "package.json": { name: "a", private: true } });
    assert.ok(!ids(findings).includes("supply-chain/no-lockfile"));
  });

  test("flags floating and mutable references, not ordinary ranges", async () => {
    const findings = await scan({
      "package.json": {
        name: "a",
        dependencies: {
          pinned: "^1.2.3",
          exact: "1.2.3",
          floating: "*",
          newest: "latest",
          branch: "github:acme/tool#main",
          sha: "github:acme/tool#5f1e2a9c3b7d4e6f8a0b1c2d3e4f5a6b7c8d9e0f"
        }
      },
      "package-lock.json": { lockfileVersion: 3 }
    });
    const floating = findings.filter((finding) => finding.ruleId === "supply-chain/floating-dependency");
    assert.deepEqual(floating.map((finding) => finding.evidence.match(/"(\w+)"/)[1]).sort(), ["floating", "newest"]);

    const mutable = findings.filter((finding) => finding.ruleId === "supply-chain/mutable-dependency-reference");
    assert.equal(mutable.length, 1, "a commit-pinned git dependency is immutable and must not be flagged");
    assert.match(mutable[0].evidence, /branch/);
  });
});

describe("install scripts", () => {
  test("flags an explicit re-enable of install scripts", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "package-lock.json": { lockfileVersion: 3 },
      ".npmrc": "ignore-scripts=false\n"
    });
    assert.ok(ids(findings).includes("supply-chain/install-scripts-unrestricted"));
  });

  test("accepts every spelling pnpm has used for the allow-list", async () => {
    // A posture rule that knows one spelling of a defense reports it missing on exactly
    // the projects that adopted the newer one. `allowBuilds` replaced
    // `onlyBuiltDependencies`; both mean the policy is declared.
    for (const key of ["onlyBuiltDependencies", "allowBuilds", "neverBuiltDependencies"]) {
      const findings = await scan({
        "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "pnpm-workspace.yaml": `${key}:\n  esbuild: true\n`
      });
      assert.ok(!ids(findings).includes("supply-chain/install-scripts-unrestricted"),
        `${key} should count as a declared policy`);
    }
  });

  test("flags a pnpm project that declares no policy at all", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      "pnpm-workspace.yaml": "packages:\n  - apps/*\n"
    });
    assert.ok(ids(findings).includes("supply-chain/install-scripts-unrestricted"));
  });
});

describe("registries", () => {
  test("flags a plain-HTTP registry and disabled certificate checks", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "package-lock.json": { lockfileVersion: 3 },
      ".npmrc": "registry=http://packages.internal/npm/\nstrict-ssl=false\n"
    });
    const registry = findings.filter((finding) => finding.ruleId === "supply-chain/untrusted-registry");
    assert.equal(registry.length, 2);
  });

  test("does not flag an HTTPS registry or a localhost mirror", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "package-lock.json": { lockfileVersion: 3 },
      ".npmrc": "registry=https://registry.npmjs.org/\n@acme:registry=http://localhost:4873/\n"
    });
    assert.ok(!ids(findings).includes("supply-chain/untrusted-registry"));
  });
});

describe("CI actions", () => {
  test("flags tag-pinned actions and accepts a full SHA", async () => {
    const findings = await scan({
      "package.json": { name: "a", dependencies: { left: "^1.0.0" } },
      "package-lock.json": { lockfileVersion: 3 },
      ".github/workflows/ci.yml": [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: third-party/deploy@main",
        "      - uses: acme/tool@5f1e2a9c3b7d4e6f8a0b1c2d3e4f5a6b7c8d9e0f  # v2.1.0"
      ].join("\n")
    });
    const pinned = findings.filter((finding) => finding.ruleId === "supply-chain/unpinned-ci-action");
    assert.equal(pinned.length, 2, "only the two tag-pinned actions should be reported");
    // A third-party action is a wider trust decision than one of GitHub's own.
    const third = pinned.find((finding) => /third-party/.test(finding.message));
    assert.equal(third.confidence, "high");
    assert.equal(pinned.find((finding) => /actions\/checkout/.test(finding.message)).confidence, "medium");
  });
});

describe("NuGet", () => {
  test("flags multiple feeds without source mapping", async () => {
    const findings = await scan({
      "App.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Serilog" Version="3.0.0" /></ItemGroup></Project>',
      "nuget.config": [
        "<configuration><packageSources>",
        '  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />',
        '  <add key="internal" value="https://packages.internal/v3/index.json" />',
        "</packageSources></configuration>"
      ].join("\n")
    });
    assert.ok(ids(findings).includes("supply-chain/nuget-dependency-confusion"));
  });

  test("does not flag when source mapping is configured", async () => {
    const findings = await scan({
      "App.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Serilog" Version="3.0.0" /></ItemGroup></Project>',
      "packages.lock.json": { version: 1 },
      "nuget.config": [
        "<configuration><packageSources>",
        '  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />',
        '  <add key="internal" value="https://packages.internal/v3/index.json" />',
        "</packageSources>",
        '<packageSourceMapping><packageSource key="internal"><package pattern="Acme.*" /></packageSource></packageSourceMapping>',
        "</configuration>"
      ].join("\n")
    });
    assert.deepEqual(ids(findings), []);
  });
});

describe("Python", () => {
  test("flags unpinned requirements and an extra index", async () => {
    const findings = await scan({
      "pyproject.toml": '[project]\nname = "svc"\n',
      "requirements.txt": "--extra-index-url https://packages.internal/simple\nrequests\nflask==3.0.0\n"
    });
    const found = ids(findings);
    assert.ok(found.includes("supply-chain/python-unpinned-requirements"));
    assert.ok(found.includes("supply-chain/python-extra-index"));
  });

  test("does not ask a hash-locked requirements file to also pin loosely", async () => {
    const findings = await scan({
      "pyproject.toml": '[project]\nname = "svc"\n',
      "requirements.txt": "flask==3.0.0 \\\n    --hash=sha256:abc123\n"
    });
    assert.ok(!ids(findings).includes("supply-chain/python-unpinned-requirements"));
  });
});

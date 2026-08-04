import { readdir } from "node:fs/promises";
import path from "node:path";
import { exists, readJson, readText, relativePath } from "../util.js";

/**
 * Supply-chain posture.
 *
 * Every other rule here asks what your code does. These ask what your build trusts, which
 * is a much larger surface and one nobody owns: the dependency you installed today
 * resolves through a version range, a registry, a lockfile that may or may not exist, and
 * an install script that runs with your developer's credentials before a single line of
 * your own code executes.
 *
 * These are posture checks, not vulnerability reports. Each one asks whether a specific
 * defense is in place — a pinned version, a committed lockfile, a scoped registry — and
 * the absence of one is not proof of compromise. It is proof that if a package you depend
 * on were compromised tomorrow, nothing here would slow it down.
 */

function lineOf(text, needle) {
  const index = text.indexOf(needle);
  if (index === -1) return 1;
  return text.slice(0, index).split(/\r?\n/).length;
}

const NODE_LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "npm-shrinkwrap.json"];

async function nodeContext(directory) {
  const manifest = await readJson(path.join(directory, "package.json"));
  if (!manifest) return null;
  const lockfiles = [];
  for (const name of NODE_LOCKFILES) {
    if (await exists(path.join(directory, name))) lockfiles.push(name);
  }
  return {
    manifest,
    lockfiles,
    packageManager: manifest.packageManager || "",
    dependencies: {
      ...manifest.dependencies,
      ...manifest.devDependencies,
      ...manifest.optionalDependencies
    }
  };
}

export const supplyChainProjectRules = [
  {
    id: "supply-chain/no-lockfile",
    category: "supply-chain",
    severity: "high",
    title: "Dependencies resolve without a lockfile",
    why: "Without a lockfile, every install resolves version ranges afresh, so the tree that ships is whatever the registry served that minute. A compromised release of any transitive dependency is picked up automatically, and the build that reproduced the bug yesterday cannot be reproduced today.",
    fix: "Commit the lockfile your package manager generates and install with the frozen flag in CI (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`) so a drifted lockfile fails the build instead of being silently rewritten.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const node = await nodeContext(context.project.directory);
      if (!node) return [];
      if (!Object.keys(node.dependencies).length) return [];
      if (node.lockfiles.length) return [];
      return [{
        file: relativePath(context.root, path.join(context.project.directory, "package.json")),
        line: 1,
        evidence: `${Object.keys(node.dependencies).length} dependencies, no lockfile`,
        message: "No lockfile sits beside this package.json, so installs are not reproducible.",
        confidence: "high"
      }];
    }
  },

  {
    id: "supply-chain/floating-dependency",
    category: "supply-chain",
    severity: "high",
    title: "Dependency pinned to whatever is newest",
    why: "A `*` or `latest` range means you install whatever was published most recently, including a version published minutes ago by someone who just took over the package. It removes the window in which a malicious release gets noticed before it reaches you.",
    fix: "Pin to a caret or exact range and let the lockfile hold the resolved version. Upgrade deliberately, through a change someone reviews.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const node = await nodeContext(context.project.directory);
      if (!node) return [];
      const manifestPath = path.join(context.project.directory, "package.json");
      const text = (await readText(manifestPath)) || "";
      const findings = [];
      for (const [name, range] of Object.entries(node.dependencies)) {
        if (typeof range !== "string") continue;
        if (!/^(?:\*|latest|x|X|)$/.test(range.trim())) continue;
        findings.push({
          file: relativePath(context.root, manifestPath),
          line: lineOf(text, `"${name}"`),
          evidence: `"${name}": "${range}"`,
          message: `\`${name}\` resolves to whatever is newest at install time.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "supply-chain/mutable-dependency-reference",
    category: "supply-chain",
    severity: "high",
    title: "Dependency fetched from a mutable reference",
    why: "A dependency pointed at a branch, a tag, or a bare repository URL is whatever that reference contains when the install runs. Tags can be moved and branches change by design, so the code you reviewed and the code you ship are only incidentally the same.",
    fix: "Pin the reference to a full commit SHA, or publish the dependency to a registry and depend on a version.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const node = await nodeContext(context.project.directory);
      if (!node) return [];
      const manifestPath = path.join(context.project.directory, "package.json");
      const text = (await readText(manifestPath)) || "";
      const findings = [];
      for (const [name, range] of Object.entries(node.dependencies)) {
        if (typeof range !== "string") continue;
        const remote = /^(?:git\+|github:|gitlab:|bitbucket:|https?:\/\/)/.test(range) || /^[\w-]+\/[\w.-]+(?:#|$)/.test(range);
        if (!remote) continue;
        // A 40-character SHA after the fragment is immutable; anything else is not.
        if (/#[0-9a-f]{40}$/i.test(range)) continue;
        findings.push({
          file: relativePath(context.root, manifestPath),
          line: lineOf(text, `"${name}"`),
          evidence: `"${name}": "${range}"`,
          message: `\`${name}\` is fetched from a reference that can change without the version changing.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "supply-chain/install-scripts-unrestricted",
    category: "supply-chain",
    severity: "high",
    title: "Dependency install scripts run unrestricted",
    why: "`postinstall` and its siblings execute with your developer's shell and credentials before any of your code runs, and before anyone has read the package. It is the shortest path from a compromised publish to a stolen token, which is why it is the vector most npm attacks actually use.",
    fix: "Restrict which dependencies may run scripts. pnpm takes an explicit `onlyBuiltDependencies` allow-list; npm and yarn can install with scripts disabled and build the few packages that genuinely need it. Never re-enable them globally to fix one package.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      const node = await nodeContext(context.project.directory);
      if (!node) return [];
      const findings = [];

      const npmrcPath = path.join(context.project.directory, ".npmrc");
      const npmrc = await readText(npmrcPath);
      if (npmrc && /^\s*ignore-scripts\s*=\s*false/m.test(npmrc)) {
        findings.push({
          file: relativePath(context.root, npmrcPath),
          line: lineOf(npmrc, "ignore-scripts"),
          evidence: "ignore-scripts=false",
          message: "Install scripts are explicitly re-enabled for every dependency.",
          confidence: "high"
        });
      }

      const usesPnpm = node.lockfiles.includes("pnpm-lock.yaml") || node.packageManager.startsWith("pnpm");
      if (usesPnpm) {
        const workspacePath = path.join(context.project.directory, "pnpm-workspace.yaml");
        const workspace = (await readText(workspacePath)) || "";
        // pnpm has spelled this policy several ways across versions — `onlyBuiltDependencies`,
        // now `allowBuilds`, plus the deny-list forms. Matching one spelling would report a
        // missing defense on exactly the projects that adopted the current one, which is the
        // worst possible direction for a posture check to be wrong in.
        const POLICY_KEYS = /(?:onlyBuiltDependencies|allowBuilds|neverBuiltDependencies|ignoredBuiltDependencies|allowedDeprecatedVersions)\s*:/;
        const declared = POLICY_KEYS.test(workspace)
          || POLICY_KEYS.test(`${JSON.stringify(node.manifest.pnpm || {}).replace(/"/g, "")}:`);
        if (/dangerouslyAllowAllBuilds\s*:\s*true/.test(workspace)) {
          findings.push({
            file: relativePath(context.root, workspacePath),
            line: lineOf(workspace, "dangerouslyAllowAllBuilds"),
            evidence: "dangerouslyAllowAllBuilds: true",
            message: "Every dependency is permitted to run build scripts, which is the default pnpm deliberately removed.",
            confidence: "high"
          });
        } else if (!declared) {
          findings.push({
            file: relativePath(context.root, path.join(context.project.directory, "package.json")),
            line: 1,
            evidence: "pnpm project with no onlyBuiltDependencies allow-list",
            message: "No `onlyBuiltDependencies` allow-list is declared, so the set of packages allowed to run scripts is implicit.",
            confidence: "low"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "supply-chain/untrusted-registry",
    category: "supply-chain",
    severity: "critical",
    title: "Packages fetched over an untrusted channel",
    why: "A registry reached over plain HTTP, or with certificate verification disabled, can be substituted by anyone on the network path. Whatever they return is installed and executed with full developer or build-agent privileges.",
    fix: "Use HTTPS for every registry and leave certificate verification on. If an internal mirror has a private certificate authority, trust that authority explicitly rather than disabling the check.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const findings = [];
      const candidates = [".npmrc", ".yarnrc.yml", ".yarnrc", "pip.conf", "pip.ini", "nuget.config", "NuGet.config", "NuGet.Config"];
      for (const name of candidates) {
        const target = path.join(context.project.directory, name);
        const text = await readText(target);
        if (!text) continue;
        const relative = relativePath(context.root, target);

        for (const match of text.matchAll(/https?:\/\/[^\s"'<>]+/g)) {
          if (!match[0].startsWith("http://")) continue;
          if (/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])/.test(match[0])) continue;
          findings.push({
            file: relative,
            line: lineOf(text, match[0]),
            evidence: match[0].slice(0, 90),
            message: "Packages are fetched over plain HTTP, which any network position can rewrite.",
            confidence: "high"
          });
        }
        if (/strict-ssl\s*=\s*false|enableStrictSsl\s*:\s*false|trusted-host\s*=/i.test(text)) {
          findings.push({
            file: relative,
            line: lineOf(text, text.match(/strict-ssl|enableStrictSsl|trusted-host/i)?.[0] || ""),
            evidence: "certificate verification disabled for the registry",
            message: "Registry certificate verification is disabled, so the endpoint's identity is never checked.",
            confidence: "high"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "supply-chain/unpinned-ci-action",
    category: "supply-chain",
    severity: "high",
    title: "CI action referenced by a movable tag",
    why: "A workflow step referenced by tag runs whatever that tag points at when the job starts, and tags are mutable by design. An attacker who gains push access to a popular action can repoint the tag and immediately execute inside every pipeline using it — with access to that pipeline's secrets. This has happened to widely used actions.",
    fix: "Pin each third-party action to a full commit SHA, with the human-readable version in a trailing comment so upgrades stay reviewable. Keep a bot updating those SHAs rather than trusting the tag.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const workflowDirectory = path.join(context.root, ".github", "workflows");
      if (!(await exists(workflowDirectory))) return [];
      let entries = [];
      try {
        entries = await readdir(workflowDirectory);
      } catch {
        return [];
      }

      const findings = [];
      for (const name of entries) {
        if (!/\.ya?ml$/i.test(name)) continue;
        const target = path.join(workflowDirectory, name);
        const text = await readText(target);
        if (!text) continue;
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length; index += 1) {
          const match = lines[index].match(/^\s*-?\s*uses\s*:\s*['"]?([\w.-]+)\/([\w.-]+(?:\/[\w.-]+)*)@([^\s'"#]+)/);
          if (!match) continue;
          const [, owner, repo, ref] = match;
          if (/^[0-9a-f]{40}$/i.test(ref)) continue;
          // First-party actions from the workflow's own repository are governed by the
          // same review process as the code, so a tag there is not a third-party risk.
          if (owner === "." || match[0].includes("./")) continue;
          findings.push({
            file: relativePath(context.root, target),
            line: index + 1,
            evidence: lines[index].trim().slice(0, 100),
            message: `\`${owner}/${repo}\` is pinned to \`${ref}\`, a reference its maintainers can repoint at any commit.`,
            confidence: owner === "actions" || owner === "github" ? "medium" : "high"
          });
        }
      }
      return findings.slice(0, 30);
    }
  },

  {
    id: "supply-chain/nuget-dependency-confusion",
    category: "supply-chain",
    severity: "high",
    title: "NuGet feeds configured without source mapping",
    why: "With more than one feed and no mapping, NuGet may resolve any package from any of them. Publishing a package to the public gallery under the name of one of your internal ones is enough to have it installed instead — the original dependency-confusion attack, and the reason source mapping exists.",
    fix: "Add `<packageSourceMapping>` to nuget.config so each package pattern resolves from exactly one feed, with your internal prefix bound to the internal feed.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      for (const name of ["nuget.config", "NuGet.config", "NuGet.Config"]) {
        const target = path.join(context.project.directory, name);
        const text = await readText(target);
        if (!text) continue;
        const sources = [...text.matchAll(/<add\s+key="[^"]*"\s+value="[^"]*"/g)].length;
        if (sources < 2) return [];
        if (/<packageSourceMapping>/i.test(text)) return [];
        return [{
          file: relativePath(context.root, target),
          line: lineOf(text, "<packageSources"),
          evidence: `${sources} package sources, no packageSourceMapping`,
          message: "Multiple feeds are configured and any of them may serve any package name.",
          confidence: "high"
        }];
      }
      return [];
    }
  },

  {
    id: "supply-chain/nuget-no-lockfile",
    category: "supply-chain",
    severity: "medium",
    title: ".NET restore is not locked",
    why: "Without a lockfile, `restore` re-resolves floating versions on every build, so the packages in a release build are not necessarily the ones that were tested or reviewed.",
    fix: "Set `RestorePackagesWithLockFile` in the project and commit the generated `packages.lock.json`, then restore with `--locked-mode` in CI.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      if (context.project.kind !== "dotnet" && context.project.kind !== "csharp") return [];
      const manifest = path.join(context.project.directory, context.project.manifest ? path.basename(context.project.manifest) : "");
      const text = (await readText(manifest)) || "";
      if (/<RestorePackagesWithLockFile>\s*true/i.test(text)) return [];
      if (await exists(path.join(context.project.directory, "packages.lock.json"))) return [];
      if (!/<PackageReference/i.test(text)) return [];
      return [{
        file: relativePath(context.root, manifest),
        line: lineOf(text, "<PackageReference"),
        evidence: "PackageReference without packages.lock.json",
        message: "Package versions are re-resolved on every restore.",
        confidence: "medium"
      }];
    }
  },

  {
    id: "supply-chain/python-unpinned-requirements",
    category: "supply-chain",
    severity: "medium",
    title: "Python requirements are not pinned",
    why: "An unpinned requirement installs whatever the index serves at build time. Combined with no hashes, there is nothing tying the artifact you tested to the artifact you deploy — a re-published version under the same number would be installed without complaint.",
    fix: "Compile pinned requirements with hashes (`pip-compile --generate-hashes`, `uv pip compile`) and install with `--require-hashes`, keeping the loose ranges in a separate input file.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      if (context.project.kind !== "python") return [];
      const findings = [];
      for (const name of ["requirements.txt", "requirements/base.txt", "requirements/prod.txt"]) {
        const target = path.join(context.project.directory, name);
        const text = await readText(target);
        if (!text) continue;
        const relative = relativePath(context.root, target);
        const lines = text.split(/\r?\n/);

        // A hashed lock file is the fixed form; do not ask it to also pin loosely.
        if (/--hash=/.test(text)) continue;

        let unpinned = 0;
        let firstLine = 1;
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index].trim();
          if (!line || line.startsWith("#") || line.startsWith("-")) continue;
          if (/[=~!<>]=|@\s*git\+.*@[0-9a-f]{40}/.test(line)) continue;
          unpinned += 1;
          if (unpinned === 1) firstLine = index + 1;
        }
        if (!unpinned) continue;
        findings.push({
          file: relative,
          line: firstLine,
          evidence: `${unpinned} requirement${unpinned === 1 ? "" : "s"} without an exact version`,
          message: `${unpinned} requirement${unpinned === 1 ? " resolves" : "s resolve"} to whatever the index serves at install time.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "supply-chain/python-extra-index",
    category: "supply-chain",
    severity: "high",
    title: "Additional package index configured alongside the public one",
    why: "`--extra-index-url` does not replace the public index, it adds to it, and pip may install from whichever offers a higher version. Anyone who publishes your internal package name publicly, at a higher version, gets installed instead.",
    fix: "Use `--index-url` to point at a single internal index that proxies the public one, so exactly one source is authoritative for every name.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const findings = [];
      for (const name of ["requirements.txt", "pip.conf", "pip.ini", "requirements/base.txt"]) {
        const target = path.join(context.project.directory, name);
        const text = await readText(target);
        if (!text || !/extra-index-url/i.test(text)) continue;
        findings.push({
          file: relativePath(context.root, target),
          line: lineOf(text, text.match(/[-\s]*extra-index-url/i)?.[0] || "extra-index-url"),
          evidence: (text.split(/\r?\n/).find((line) => /extra-index-url/i.test(line)) || "").trim().slice(0, 90),
          message: "An extra index is consulted in addition to the default, so package names are resolvable from either.",
          confidence: "high"
        });
      }
      return findings;
    }
  }
];

import { spawn } from "node:child_process";
import path from "node:path";
import { REPORT_DIR, toPosix } from "./util.js";

function git(root, args) {
  return new Promise((resolve) => {
    const child = spawn("git", args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", () => resolve({ ok: false, stdout: "", stderr: "git not available" }));
    child.on("close", (code) => resolve({ ok: code === 0, stdout: stdout.trim(), stderr: stderr.trim() }));
  });
}

export async function isRepository(root) {
  const result = await git(root, ["rev-parse", "--is-inside-work-tree"]);
  return result.ok && result.stdout === "true";
}

/**
 * Work out what to diff against when the caller did not say.
 *
 * A regression check compares the branch to where it started, so the useful base is the
 * merge point with the trunk, not the trunk's current tip — otherwise every commit
 * someone else lands on main shows up as a change you introduced.
 */
export async function resolveBase(root, explicit) {
  if (explicit) return { ref: explicit, reason: "specified with --base" };

  const candidates = ["origin/main", "origin/master", "main", "master", "origin/develop", "develop"];
  const head = await git(root, ["rev-parse", "--abbrev-ref", "HEAD"]);
  let onTrunk = false;

  for (const candidate of candidates) {
    const exists = await git(root, ["rev-parse", "--verify", "--quiet", candidate]);
    if (!exists.ok) continue;
    // Diffing the trunk against itself yields nothing; on the trunk the only meaningful
    // comparison is against the working tree.
    if (head.ok && head.stdout === candidate.replace(/^origin\//, "")) {
      onTrunk = true;
      continue;
    }
    const mergeBase = await git(root, ["merge-base", "HEAD", candidate]);
    if (mergeBase.ok && mergeBase.stdout) {
      return { ref: mergeBase.stdout, reason: `merge-base with ${candidate}`, branch: candidate };
    }
  }

  return {
    ref: null,
    reason: onTrunk
      ? `on ${head.stdout} — comparing against uncommitted changes only`
      : "no trunk branch found — comparing against uncommitted changes only"
  };
}

/**
 * Files changed relative to `base`, plus anything uncommitted. Both matter for a
 * pre-commit check: the point is to catch what you are about to introduce, and work in
 * progress has not been committed yet.
 */
export async function changedFiles(root, base) {
  if (!(await isRepository(root))) {
    return { available: false, reason: "not a git repository", files: new Set() };
  }

  const files = new Set();
  const collect = (output) => {
    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      // Tripwire's own artifacts are untracked output, not a change the caller made —
      // counting them makes every scan after the first look like it touched more files.
      if (!trimmed || trimmed.split("/").includes(REPORT_DIR)) continue;
      files.add(toPosix(trimmed));
    }
  };

  if (base) {
    const committed = await git(root, ["diff", "--name-only", "--diff-filter=ACMR", `${base}...HEAD`]);
    if (committed.ok) collect(committed.stdout);
  }

  const unstaged = await git(root, ["diff", "--name-only", "--diff-filter=ACMR"]);
  if (unstaged.ok) collect(unstaged.stdout);

  const staged = await git(root, ["diff", "--name-only", "--diff-filter=ACMR", "--cached"]);
  if (staged.ok) collect(staged.stdout);

  const untracked = await git(root, ["ls-files", "--others", "--exclude-standard"]);
  if (untracked.ok) collect(untracked.stdout);

  return { available: true, files };
}

/**
 * Restrict findings to files the caller touched.
 *
 * Project-scope rules still run against the whole tree — an unused export or a stale
 * instruction file can only be judged with full context — but a finding is only reported
 * when it sits in a changed file. That keeps a regression check about the change without
 * making the analysis behind it narrower than it needs to be.
 */
export function filterToChanged(findings, changed, projectRelative) {
  if (!changed.size) return [];
  return findings.filter((finding) => {
    const repoPath = projectRelative === "." ? finding.file : toPosix(path.join(projectRelative, finding.file));
    return changed.has(repoPath) || changed.has(finding.file);
  });
}

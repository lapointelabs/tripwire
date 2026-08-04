import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { explainRule, findRule } from "../src/explain.js";
import { filterToChanged } from "../src/git.js";
import { PLAYBOOK } from "../src/playbook.js";
import { allRules } from "../src/rules/index.js";
import { detectHarnesses, HARNESSES, installSkills } from "../src/skills.js";
import { createPalette } from "../src/util.js";

const scratch = [];
after(async () => {
  for (const directory of scratch) await rm(directory, { recursive: true, force: true });
});

async function workspace() {
  const directory = await mkdtemp(path.join(tmpdir(), "tripwire-skills-"));
  scratch.push(directory);
  return directory;
}

describe("skill installation", () => {
  test("installs only the harnesses present in the repository", async () => {
    const root = await workspace();
    await mkdir(path.join(root, ".cursor"), { recursive: true });

    const detected = await detectHarnesses(root);
    assert.deepEqual(detected, ["cursor"]);

    const results = await installSkills(root, detected);
    assert.equal(results.length, 1);
    assert.equal(results[0].status, "written");
    const written = await readFile(path.join(root, HARNESSES.cursor.file), "utf8");
    assert.match(written, /^---\nname: tripwire\n/);
    assert.match(written, /@lapointelabs\/tripwire/);
  });

  test("installs Cursor as a skill bundle, not a passive rule", async () => {
    const root = await workspace();
    await installSkills(root, ["cursor"]);

    // Cursor reads .cursor/skills/, never .claude/skills/ — a shared path would silently
    // install nothing Cursor can see.
    assert.equal(HARNESSES.cursor.file, path.join(".cursor", "skills", "tripwire", "SKILL.md"));
    const skill = await readFile(path.join(root, HARNESSES.cursor.file), "utf8");
    assert.match(skill, /^---\nname: tripwire\ndescription: /);
    assert.match(skill, /disable-model-invocation: true/, "skills load when named, not ambiently");
    assert.doesNotMatch(skill, /alwaysApply/, "this is a skill, not an .mdc rule");

    // References must exist, because SKILL.md defers the long-form workflow to them.
    const triage = await readFile(path.join(root, ".cursor/skills/tripwire/references/triage.md"), "utf8");
    assert.match(triage, /Do not commit/i);
    const rules = await readFile(path.join(root, ".cursor/skills/tripwire/references/rules.md"), "utf8");
    assert.match(rules, /injection\/sql-interpolation/);
    assert.match(skill, /references\/triage\.md/, "SKILL.md must point at its references");
  });

  test("keeps the entry file short enough to stay cheap to load", async () => {
    const root = await workspace();
    await installSkills(root, ["cursor"]);
    const skill = await readFile(path.join(root, HARNESSES.cursor.file), "utf8");
    assert.ok(skill.split("\n").length < 120, "SKILL.md should defer detail to references");
  });

  test("writes valid frontmatter for every harness", async () => {
    const root = await workspace();
    await installSkills(root, Object.keys(HARNESSES));

    const claude = await readFile(path.join(root, HARNESSES.claude.file), "utf8");
    assert.match(claude, /^---\nname: tripwire\ndescription: .+\nversion: "/s);

    const copilot = await readFile(path.join(root, HARNESSES.copilot.file), "utf8");
    assert.match(copilot, /^---\napplyTo: "\*\*"/);

    for (const harness of Object.values(HARNESSES)) {
      const content = await readFile(path.join(root, harness.file), "utf8");
      assert.match(content, /scan --scope changed/, `${harness.file} must document the regression check`);
    }
  });

  test("appends to an existing AGENTS.md without destroying it, and replaces on reinstall", async () => {
    const root = await workspace();
    await writeFile(path.join(root, "AGENTS.md"), "# Project\n\nUse tabs, not spaces.\n", "utf8");

    await installSkills(root, ["agents"]);
    let content = await readFile(path.join(root, "AGENTS.md"), "utf8");
    assert.match(content, /Use tabs, not spaces\./, "existing instructions must survive");
    assert.match(content, /Tripwire/);

    const second = await installSkills(root, ["agents"]);
    assert.equal(second[0].status, "updated");
    content = await readFile(path.join(root, "AGENTS.md"), "utf8");
    assert.equal(content.match(/tripwire:start/g).length, 1, "reinstall must not stack duplicates");
    assert.match(content, /Use tabs, not spaces\./);
  });

  test("refuses to clobber a hand-written skill file unless forced", async () => {
    const root = await workspace();
    const target = path.join(root, HARNESSES.claude.file);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, "---\nname: tripwire\n---\n\nMy own notes.\n", "utf8");

    const skipped = await installSkills(root, ["claude"]);
    assert.equal(skipped[0].status, "skipped");
    assert.match(await readFile(target, "utf8"), /My own notes/);

    const forced = await installSkills(root, ["claude"], { force: true });
    assert.equal(forced[0].status, "written");
    assert.doesNotMatch(await readFile(target, "utf8"), /My own notes/);
  });
});

describe("playbook", () => {
  test("tells the agent not to commit and to accept rejected findings", () => {
    assert.match(PLAYBOOK, /Do not commit/i);
    assert.match(PLAYBOOK, /rotated/i, "must escalate credential rotation to a human");
    assert.match(PLAYBOOK, /successful outcome/i, "rejecting a finding must be a valid outcome");
    assert.match(PLAYBOOK, /Never suppress/i);
  });
});

describe("explain", () => {
  test("resolves an exact id and reports ambiguity otherwise", () => {
    assert.equal(findRule("injection/sql-interpolation").rule.id, "injection/sql-interpolation");
    const fuzzy = findRule("sql");
    assert.equal(fuzzy.rule, null);
    assert.ok(fuzzy.matches.length > 1);
    assert.equal(findRule("no-such-rule").matches.length, 0);
  });

  test("renders fix guidance and known false positives", () => {
    const palette = createPalette(false);
    const output = explainRule(findRule("structure/await-in-loop").rule, palette);
    assert.match(output, /Why it matters/);
    assert.match(output, /Done when/);
    assert.match(output, /Known false positives/);
    assert.match(output, /genuinely depends on the previous result/);
    assert.doesNotMatch(output, /at the file/, "placeholder wording must read naturally");
  });

  test("every rule can be explained without throwing", () => {
    const palette = createPalette(false);
    for (const rule of allRules) {
      const output = explainRule(rule, palette);
      assert.ok(output.includes(rule.title), `${rule.id} should render its title`);
    }
  });
});

describe("instruction-file references", () => {
  async function scanInstructions(text, files = {}) {
    const root = await workspace();
    await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "t", scripts: { test: "node --test" } }), "utf8");
    await writeFile(path.join(root, "CLAUDE.md"), text, "utf8");
    for (const [name, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true });
      await writeFile(path.join(root, name), content, "utf8");
    }
    const { detectProjects } = await import("../src/detect.js");
    const { scanProject } = await import("../src/scan.js");
    const [project] = await detectProjects(root);
    const result = await scanProject({ root, project, only: ["context/stale-instruction-reference"] });
    return result.findings;
  }

  test("flags paths and scripts that do not exist", async () => {
    const findings = await scanInstructions("Entry is `src/index.js`.\nRun `npm run build`.\n");
    assert.equal(findings.length, 2);
    assert.ok(findings.some((finding) => /src\/index\.js/.test(finding.message)));
    assert.ok(findings.some((finding) => /build/.test(finding.message)));
  });

  test("does not flag slash commands, rule ids, or branch names as paths", async () => {
    // Every one of these contains a slash but none is a file. Instruction files are
    // full of them, and treating them as paths makes the rule unusable.
    const findings = await scanInstructions([
      "Use `/tripwire` for a security pass.",
      "Rule `secrets/committed-credential` blocks commits.",
      "Branch from `feature/new-checkout`.",
      "Install `@lapointelabs/tripwire`.",
      "See `context/injection-in-agent-context`."
    ].join("\n"));
    assert.deepEqual(findings, []);
  });

  test("does not flag a path that exists", async () => {
    const findings = await scanInstructions("Entry is `src/api.js`.", { "src/api.js": "export const a = 1;\n" });
    assert.deepEqual(findings, []);
  });

  test("does not flag its own installed skill file", async () => {
    const root = await workspace();
    await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "t" }), "utf8");
    await installSkills(root, ["claude"]);

    const { detectProjects } = await import("../src/detect.js");
    const { scanProject } = await import("../src/scan.js");
    const [project] = await detectProjects(root);
    const result = await scanProject({ root, project });
    const selfFindings = result.findings.filter((finding) => finding.file.includes("SKILL.md"));
    assert.deepEqual(selfFindings, [], "Tripwire must not report its own skill file");
  });
});

describe("skill command override", () => {
  test("uses a custom invocation across the whole bundle", async () => {
    const root = await workspace();
    await installSkills(root, ["cursor"], { command: "pnpm tripwire" });

    const skill = await readFile(path.join(root, HARNESSES.cursor.file), "utf8");
    assert.match(skill, /pnpm tripwire scan --scope changed/);
    assert.match(skill, /pnpm tripwire explain/);
    assert.doesNotMatch(skill, /npx @lapointelabs/);

    // The bundled playbook is a copy, so it needs substituting too — otherwise the
    // entry file points at a working command and the reference at a broken one.
    const triage = await readFile(path.join(root, ".cursor/skills/tripwire/references/triage.md"), "utf8");
    assert.match(triage, /pnpm tripwire scan/);
    assert.doesNotMatch(triage, /npx @lapointelabs/);
  });

  test("substitutes the command in the appended AGENTS.md section too", async () => {
    const root = await workspace();
    await installSkills(root, ["agents"], { command: "pnpm tripwire" });
    const content = await readFile(path.join(root, "AGENTS.md"), "utf8");
    assert.match(content, /pnpm tripwire scan --scope changed/);
    assert.doesNotMatch(content, /npx @lapointelabs/);
  });

  test("still recognizes its own file for overwrite protection", async () => {
    const root = await workspace();
    await installSkills(root, ["cursor"], { command: "tripwire" });
    const second = await installSkills(root, ["cursor"], { command: "tripwire" });
    assert.equal(second[0].status, "written", "a Tripwire-written file must be replaceable without --force");
  });
});

describe("changed-file scoping", () => {
  test("keeps findings in changed files and drops the rest", () => {
    const findings = [
      { file: "src/bad.js", line: 1 },
      { file: "src/clean.js", line: 2 }
    ];
    const kept = filterToChanged(findings, new Set(["src/bad.js"]), ".");
    assert.deepEqual(kept.map((finding) => finding.file), ["src/bad.js"]);
  });

  test("resolves project-relative paths against the repository root", () => {
    const findings = [{ file: "src/bad.js", line: 1 }];
    const kept = filterToChanged(findings, new Set(["services/api/src/bad.js"]), "services/api");
    assert.equal(kept.length, 1);
  });

  test("reports nothing when nothing changed", () => {
    assert.deepEqual(filterToChanged([{ file: "a.js" }], new Set(), "."), []);
  });
});

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { listProviders, resolveProvider, triageFindings } from "./ai.js";
import { auditProject, VULNERABLE_DEPENDENCY_RULE } from "./audit.js";
import { loadConfig, resolveSelection, unknownEngines } from "./config.js";
import { detectProjects, findAgentContextFiles, findAgentSurfaceFiles, groupByStack } from "./detect.js";
import { DOMAINS, ENGINES, planEngines, reconcile, relativizer, runEngines, uncoveredDomains } from "./engines/index.js";
import { explainRule, findRule } from "./explain.js";
import { changedFiles, filterToChanged, resolveBase } from "./git.js";
import { PLAYBOOK } from "./playbook.js";
import { DEFAULT_COMMAND, detectHarnesses, HARNESSES, installSkills } from "./skills.js";
import { renderFixPlan } from "./report/fixplan.js";
import { renderReportMarkdown } from "./report/markdown.js";
import { renderSarif } from "./report/sarif.js";
import { renderTerminalReport } from "./report/terminal.js";
import { allRules, CATEGORIES, SEVERITIES } from "./rules/index.js";
import { compareFindings, scanAcrossProjects, scanProject } from "./scan.js";
import { scoreProject } from "./score.js";
import { artifactDirFor, createPalette, flag, flagList, parseArgs, readJson } from "./util.js";
import { VERSION } from "./version.js";

const HELP = `tripwire ${VERSION} — find what hurts your users and misleads your agents

Usage:
  tripwire scan [PATH]        Scan a project and write a report and a fix plan.
  tripwire list [PATH]        List detected projects, grouped by stack.
  tripwire explain RULE       Explain one rule, including its false positives.
  tripwire playbook           Print the agent triage playbook.
  tripwire skills install     Install Tripwire as a skill for your coding agents.
  tripwire rules              List every rule.
  tripwire providers          List model providers for the triage layer.
  tripwire engines            List external scan engines and what each one covers.

Scan options:
  --scope changed|all       Report only findings in changed files. Default: all.
  --base REF                Base for --scope changed. Default: merge-base with trunk.
  --score                   Print only the numeric score.
  --project NAME|PATH|all   Choose a project without the interactive picker.
  --only ID|CATEGORY        Run only these rules or categories (repeatable).
  --skip ID|CATEGORY        Skip these rules or categories (repeatable).
  --all                     Show every finding in the terminal, not a summary.
  --fail-on LEVEL           Exit non-zero at critical|high|medium|low. Default: never.
  --out DIR                 Also write report.md and SARIF here. Default: a cache
                            directory outside the repository.
  --json                    Print findings as JSON to stdout and write no files.
  --audit                   Also run the ecosystem's vulnerability auditor
                            (npm/pnpm/yarn audit, dotnet, pip-audit) and include
                            its results. Spawns a subprocess and uses the network.
  --no-color                Disable colored output.

External engines (bring your own tools):
  --engines [LIST]          Run external engines and fold their findings into this
                            report. Default when bare: auto — every installed engine.
                            Also: all, none, or a list (semgrep,trufflehog).
  --offline                 Refuse any engine that needs the network, and disable
                            credential verification. For air-gapped build agents.

  Nothing is bundled, downloaded, or auto-installed. Tripwire runs the binaries you
  already have and normalizes their output into one finding model, one score, and one
  fix plan. Commercial engines use your key from your environment; Tripwire reads no
  key file, writes none, and proxies nothing. Engines that did not run are named in
  the report along with what went unchecked.

Skill options:
  --harness LIST            claude, cursor, copilot, agents. Default: detected.
  --command CMD             How skills should invoke Tripwire.
                            Default: npx @lapointelabs/tripwire@latest
  --force                   Overwrite a skill file Tripwire did not write.

Model triage (bring your own key):
  --provider NAME           anthropic | openai | cursor | ollama.
                            Default: whichever key is set.
  --model NAME              Model id. Default: the provider's recommended model.
  --api-key KEY             Overrides the environment variable.
  --base-url URL            For self-hosted or proxied endpoints.
  --budget N                Maximum findings to send for triage. Default: 250.
  --no-ai                   Skip triage entirely and report pattern confidence only.

The deterministic scan needs no API key. Triage is an optional second pass that
confirms or refutes uncertain findings; without it, low-confidence findings are
reported as leads rather than conclusions.
`;

function write(value = "") {
  process.stdout.write(`${value}\n`);
}

export async function main(argv) {
  const { positionals, flags } = parseArgs(argv);
  // Match against the known verbs rather than guessing from the shape of the argument,
  // so `tripwire services/billing` scans that path instead of reporting it as a command.
  const COMMANDS = new Set(["scan", "list", "rules", "providers", "engines", "explain", "playbook", "skills", "help"]);
  const named = positionals[0] && COMMANDS.has(positionals[0]);
  const command = named ? positionals[0] : "scan";
  const target = (named ? positionals[1] : positionals[0]) || ".";

  if (flags.help || command === "help") return write(HELP);
  if (flags.version) return write(VERSION);

  switch (command) {
    case "scan": return commandScan(path.resolve(target), flags);
    case "list": return commandList(path.resolve(target), flags);
    case "rules": return commandRules(flags);
    case "providers": return commandProviders(flags);
    case "engines": return commandEngines(path.resolve(target), flags);
    case "explain": return commandExplain(target, flags);
    case "playbook": return write(PLAYBOOK);
    case "skills": return commandSkills(positionals, flags);
    default:
      throw new Error(`unknown command "${command}". Run tripwire --help.`);
  }
}

function commandExplain(query, flags) {
  const palette = createPalette(!flags["no-color"]);
  if (!query || query === ".") {
    throw new Error("explain needs a rule id, e.g. tripwire explain injection/sql-interpolation");
  }
  const { rule, matches } = findRule(query);
  if (!rule) {
    if (!matches.length) throw new Error(`no rule matching "${query}". Run "tripwire rules" to list them.`);
    write("");
    write(`  ${matches.length} rules match "${query}":`);
    write("");
    for (const candidate of matches) write(`    ${candidate.id.padEnd(38)} ${candidate.title}`);
    write("");
    return;
  }
  if (flags.json) {
    return write(JSON.stringify({
      id: rule.id, category: rule.category, severity: rule.severity, title: rule.title,
      why: rule.why, fix: rule.fix, confidence: rule.confidence, requires: rule.requires || null,
      languages: rule.languages || "project"
    }, null, 2));
  }
  write(explainRule(rule, palette));
}

async function commandSkills(positionals, flags) {
  const palette = createPalette(!flags["no-color"]);
  const action = positionals[1] || "install";
  const root = path.resolve(flag(flags, "root", process.cwd()));

  if (action === "list") {
    const detected = await detectHarnesses(root);
    write("");
    for (const [id, harness] of Object.entries(HARNESSES)) {
      const status = detected.includes(id) ? palette.green("detected") : palette.dim("not detected");
      write(`  ${palette.bold(id.padEnd(10))} ${harness.label.padEnd(44)} ${status}`);
      write(`  ${" ".repeat(10)} ${palette.dim(harness.file)}`);
    }
    write("");
    return;
  }

  if (action !== "install") {
    throw new Error(`unknown skills action "${action}". Expected "install" or "list".`);
  }

  const requested = flagList(flags, "harness").flatMap((value) => value.split(/[,\s]+/)).filter(Boolean);
  const detected = await detectHarnesses(root);
  // With nothing detected, install the two most portable targets rather than nothing:
  // a Claude skill and an AGENTS.md section that most other harnesses already read.
  const targets = requested.length ? requested : (detected.length ? detected : ["claude", "agents"]);

  const results = await installSkills(root, targets, {
    force: Boolean(flags.force),
    command: flag(flags, "command", DEFAULT_COMMAND)
  });
  write("");
  for (const result of results) {
    const mark = { written: palette.green("installed"), updated: palette.green("updated"), appended: palette.green("appended"), skipped: palette.yellow("skipped"), unknown: palette.red("unknown") }[result.status];
    write(`  ${mark} ${palette.blue(result.file || result.id)}`);
    if (result.message) write(`    ${palette.dim(result.message)}`);
  }
  write("");
  const installedSkill = results.some((result) => result.count && result.status === "written");
  if (installedSkill) {
    // Skills declare `disable-model-invocation`, so they load when named, not ambiently.
    // Saying otherwise would set an expectation the install does not meet.
    write(`  ${palette.dim("Invoke it with /tripwire, or ask your agent to \"run tripwire\".")}`);
    write(`  ${palette.dim("Restart or reload your editor if the skill does not appear.")}`);
  } else {
    write(`  ${palette.dim("Your agents will now run Tripwire after code changes and on /tripwire.")}`);
  }
  if (!requested.length && !detected.length) {
    write(`  ${palette.dim("No harness config was detected — installed the portable defaults. Use --harness to target others.")}`);
  }
  write("");
}

async function commandList(root, flags) {
  const palette = createPalette(!flags["no-color"]);
  const projects = await detectProjects(root);
  if (!projects.length) {
    return write(`No projects detected under ${root}. Tripwire looks for package.json, *.csproj, pyproject.toml, go.mod, Cargo.toml, Gemfile, composer.json, and pom.xml.`);
  }
  if (flags.json) return write(JSON.stringify(projects.map(publicProject), null, 2));

  write("");
  write(`${palette.bold(`${projects.length} project${projects.length === 1 ? "" : "s"}`)} under ${palette.dim(root)}`);
  write("");
  for (const group of groupByStack(projects)) {
    write(`  ${palette.bold(group.stack)}`);
    for (const project of group.projects) {
      const tags = [];
      if (project.aiPackages.length) tags.push("model calls");
      if (project.dbPackages.length) tags.push("database");
      write(`    ${project.name.padEnd(28)} ${palette.dim(project.relative)}${tags.length ? palette.cyan(`  ${tags.join(", ")}`) : ""}`);
    }
    write("");
  }
}

function commandRules(flags) {
  const palette = createPalette(!flags["no-color"]);
  if (flags.json) {
    return write(JSON.stringify(allRules.map((rule) => ({
      id: rule.id, category: rule.category, severity: rule.severity, title: rule.title,
      languages: rule.languages || "project", requires: rule.requires || null, why: rule.why, fix: rule.fix
    })), null, 2));
  }
  write("");
  for (const category of Object.keys(CATEGORIES)) {
    const rules = allRules.filter((rule) => rule.category === category);
    if (!rules.length) continue;
    write(`  ${palette.bold(CATEGORIES[category].label)}`);
    for (const severity of SEVERITIES) {
      for (const rule of rules.filter((item) => item.severity === severity)) {
        const gate = rule.requires ? palette.dim(` (needs ${rule.requires})`) : "";
        write(`    ${severityTag(rule.severity, palette)} ${rule.id.padEnd(38)} ${rule.title}${gate}`);
      }
    }
    write("");
  }
  write(`  ${palette.dim(`${allRules.length} rules total.`)}`);
  write("");
}

async function commandProviders(flags) {
  const palette = createPalette(!flags["no-color"]);
  write("");
  for (const provider of listProviders()) {
    const configured = provider.envKeys.some((key) => process.env[key]);
    const key = provider.envKeys.length
      ? (configured ? palette.green("key found") : palette.dim(`set ${provider.envKeys[0]}`))
      : palette.dim("no key needed");

    let sdk;
    try {
      await import(provider.package);
      sdk = palette.dim("sdk installed");
    } catch {
      sdk = palette.yellow(`npm i ${provider.package}`);
    }

    write(`  ${palette.bold(provider.id.padEnd(11))} ${provider.label.padEnd(22)} ${palette.dim(provider.defaultModel.padEnd(16))} ${key.padEnd(24)} ${sdk}`);
  }
  write("");
  write(palette.dim("  Pass --provider to override auto-detection, --model to change the model."));
  write(palette.dim("  Cursor's SDK is an optional peer — install it only if you want Cursor triage."));
  write("");
}

/**
 * What Tripwire can delegate to, and what it would do for you if you installed it.
 *
 * Deliberately a full inventory rather than only what is present. The reason to read this
 * is to find out what is *not* being checked, which is exactly the information a list of
 * installed tools cannot give you.
 */
async function commandEngines(root, flags) {
  const palette = createPalette(!flags["no-color"]);
  const config = await loadConfig(root);
  const context = await engineContext(root, null, config, { selection: "all", offline: Boolean(flags.offline) });
  const plan = await planEngines(context);

  if (flags.json) {
    return write(JSON.stringify(plan.map((entry) => ({
      id: entry.engine.id,
      label: entry.engine.label,
      domain: entry.engine.domain,
      covers: entry.engine.covers,
      install: entry.engine.install,
      homepage: entry.engine.homepage,
      paid: Boolean(entry.engine.paid),
      network: Boolean(entry.engine.network),
      byok: entry.engine.byok || null,
      available: entry.run,
      status: entry.status,
      reason: entry.reason || null
    })), null, 2));
  }

  write("");
  for (const [domain, detail] of Object.entries(DOMAINS)) {
    const entries = plan.filter((entry) => entry.engine.domain === domain);
    if (!entries.length) continue;
    write(`  ${palette.bold(detail.label)}  ${palette.dim(`Tripwire natively: ${detail.native}`)}`);
    for (const entry of entries) {
      const { engine } = entry;
      const status = entry.run
        ? palette.green("ready")
        : entry.status === "no-key" ? palette.yellow("needs key")
          : entry.status === "not-applicable" ? palette.dim("n/a here")
            : palette.dim("not installed");
      const cost = engine.paid ? palette.yellow(" · commercial, BYOK") : "";
      write(`    ${palette.bold(engine.id.padEnd(17))} ${status.padEnd(22)} ${palette.dim(engine.covers)}${cost}`);
      if (!entry.run) write(`    ${" ".repeat(17)} ${palette.dim(entry.reason)}`);
      if (engine.byok && !engine.byok.required) {
        const set = engine.byok.env.some((name) => process.env[name]);
        write(`    ${" ".repeat(17)} ${palette.dim(`${engine.byok.env.join(" / ")} ${set ? "found" : "not set"} — unlocks ${engine.byok.unlocks}`)}`);
      }
      if (engine.fills) write(`    ${" ".repeat(17)} ${palette.cyan("fills:")} ${palette.dim(engine.fills)}`);
    }
    write("");
  }

  write(palette.dim(`  ${plan.filter((entry) => entry.run).length} of ${ENGINES.length} ready. Run them with: tripwire scan --engines`));
  write(palette.dim("  Nothing is bundled or auto-installed — Tripwire runs the binaries you install."));
  if (config.file) write(palette.dim(`  Config: ${config.filename}`));
  for (const warning of config.warnings) write(palette.yellow(`  config: ${warning}`));
  write("");
}

/** The shared inputs every engine decision needs, gathered once. */
async function engineContext(root, project, config, { selection, offline, onProgress }) {
  const [agentFiles, surface] = await Promise.all([
    findAgentContextFiles(root),
    findAgentSurfaceFiles(root)
  ]);
  return {
    root,
    project,
    projectDir: project?.directory || root,
    manifest: project?.manifest || "package.json",
    config: config.engines || {},
    selection,
    offline: Boolean(offline),
    onProgress,
    agentFiles: agentFiles.map((entry) => entry.relative),
    mcpConfigs: surface.mcpConfigs.map((entry) => entry.absolute),
    skills: surface.skills.map((entry) => entry.absolute),
    toRelative: relativizer(root)
  };
}

async function commandScan(root, flags) {
  const palette = createPalette(!flags["no-color"]);
  const projects = await detectProjects(root);
  if (!projects.length) {
    throw new Error(`no projects detected under ${root}. Run "tripwire list ${root}" to see what Tripwire looks for.`);
  }

  const config = await loadConfig(root);
  const selected = await selectProjects(projects, flags, palette);
  const only = flagList(flags, "only");
  const skip = flagList(flags, "skip");

  const quiet = Boolean(flags.json || flags.score);
  const engineSelection = resolveSelection(flags.engines, config);
  const offline = Boolean(flags.offline ?? config.scan?.offline);

  if (!quiet) {
    for (const warning of config.warnings) process.stderr.write(`tripwire: ${config.filename}: ${warning}\n`);
  }
  const unknown = unknownEngines(engineSelection);
  if (unknown.length) {
    throw new Error(`unknown engine${unknown.length === 1 ? "" : "s"} ${unknown.join(", ")}. Run "tripwire engines" for the list.`);
  }

  const scope = String(flag(flags, "scope", "all")).toLowerCase();
  if (!["all", "changed"].includes(scope)) throw new Error(`--scope expects "all" or "changed"`);

  let changed = null;
  if (scope === "changed") {
    const base = await resolveBase(root, flag(flags, "base", null));
    const result = await changedFiles(root, base.ref);
    if (!result.available) {
      if (!quiet) process.stderr.write(`tripwire: ${result.reason} — scanning everything instead.\n`);
    } else {
      changed = { files: result.files, base };
      if (!quiet && !result.files.size) {
        process.stderr.write(`tripwire: no changed files against ${base.reason}. Nothing to check.\n`);
      }
    }
  }

  const results = [];
  for (const project of selected) {
    if (!quiet) process.stderr.write(`${palette.dim(`scanning ${project.relative}…`)}\r`);

    const result = await scanProject({ root, project, only, skip });
    // Scope narrows what is *reported*, never what is analysed: an unused export or a
    // stale instruction reference can only be judged against the whole project.
    if (changed) {
      result.findings = filterToChanged(result.findings, changed.files, project.relative);
      result.scope = { mode: "changed", base: changed.base.reason, files: changed.files.size };
    }
    if (flags.audit) {
      if (!quiet) process.stderr.write(`${palette.dim(`auditing ${project.relative}…`)}\r`);
      result.audit = await auditProject(project, { root });
      for (const item of result.audit.findings) {
        result.findings.push({
          id: `${VULNERABLE_DEPENDENCY_RULE.id}:${item.file}:${item.evidence}`,
          ruleId: VULNERABLE_DEPENDENCY_RULE.id,
          category: VULNERABLE_DEPENDENCY_RULE.category,
          severity: item.severity,
          title: VULNERABLE_DEPENDENCY_RULE.title,
          why: VULNERABLE_DEPENDENCY_RULE.why,
          fix: VULNERABLE_DEPENDENCY_RULE.fix,
          file: item.file,
          line: item.line,
          endLine: item.line,
          evidence: item.evidence,
          message: item.message,
          confidence: item.confidence,
          // An advisory is authoritative; sending it to a model to second-guess wastes
          // tokens on a question the ecosystem already answered.
          aiTriage: false,
          verdict: null
        });
      }
      if (!quiet) process.stderr.write(`${" ".repeat(60)}\r`);
    }

    if (engineSelection !== "none") {
      const context = await engineContext(root, project, config, {
        selection: engineSelection,
        offline,
        onProgress: ({ engine }) => {
          if (!quiet) process.stderr.write(`${palette.dim(`${engine} on ${project.relative}…`)}\r`);
        }
      });
      const outcome = await runEngines(context);
      result.engines = { coverage: outcome.coverage, uncovered: uncoveredDomains(outcome.coverage), offline };
      result.findings.push(...outcome.findings);
      if (changed) {
        result.findings = filterToChanged(result.findings, changed.files, project.relative);
      }
      // Two engines and a native rule can all land on the same line. Collapsing them is
      // the difference between one harness and five CI steps stapled together.
      const before = result.findings.length;
      result.findings = reconcile(result.findings).sort(compareFindings);
      result.engines.deduplicated = before - result.findings.length;
      if (!quiet) process.stderr.write(`${" ".repeat(60)}\r`);
    }

    result.summary = scoreProject(result.findings, result.stats);
    result.ai = await runTriage(result, flags, root, palette);
    // Triage can refute findings, which changes the score — recompute after it runs.
    result.summary = scoreProject(result.findings, result.stats);
    results.push(result);

    if (!quiet) process.stderr.write(`${" ".repeat(60)}\r`);
  }

  // Reachability spans assemblies, so it runs once over every project scanned.
  await scanAcrossProjects(results, { only, skip });
  for (const result of results) result.summary = scoreProject(result.findings, result.stats);

  if (flags.score) {
    for (const result of results) write(String(result.summary.score));
    return applyFailOn(results, flags);
  }

  if (flags.json) {
    return write(JSON.stringify(results.map((result) => ({
      project: publicProject(result.project),
      summary: result.summary,
      stats: result.stats,
      scope: result.scope || { mode: "all" },
      gatedRules: result.gatedRules,
      engines: result.engines || null,
      audit: result.audit || null,
      triage: result.ai,
      findings: result.findings
    })), null, 2));
  }

  const meta = {
    version: VERSION,
    scannedAt: new Date().toISOString().replace("T", " ").slice(0, 16),
    verifyCommands: await verifyCommands(selected[0])
  };

  for (const result of results) {
    write(renderTerminalReport(result, palette, { all: Boolean(flags.all) }));
    const written = await writeArtifacts(result, meta, flags);
    const plan = written.files[0];
    // Relative only when it actually reads better — a path that climbs out of the working
    // directory with `../../..` is worse than the absolute one.
    const relative = path.relative(process.cwd(), plan);
    const shown = relative.startsWith("..") ? plan : relative;

    if (result.summary.total) {
      write(`  ${palette.cyan("Fix plan")} ${palette.blue(shown)}`);
      write(`  ${palette.dim(`Hand that to a coding agent, or work it yourself top to bottom.${written.inRepo ? "" : " Nothing was written into your repository."}`)}`);
    } else {
      write(`  ${palette.dim(`Nothing to fix. Details: ${shown.replace(/FIX_PLAN\.md$/, "")}`)}`);
    }
    write("");
  }

  applyFailOn(results, flags);
}

function applyFailOn(results, flags) {
  const failOn = flag(flags, "fail-on", null);
  if (!failOn || failOn === "never") return;
  const threshold = SEVERITIES.indexOf(String(failOn).toLowerCase());
  if (threshold === -1) throw new Error(`--fail-on expects one of ${SEVERITIES.join(", ")}`);
  const breached = results.some((result) => SEVERITIES
    .slice(0, threshold + 1)
    .some((severity) => (result.summary.bySeverity[severity] || 0) > 0));
  if (breached) {
    process.stderr.write(`tripwire: findings at or above "${failOn}" — failing as requested.\n`);
    process.exitCode = 1;
  }
}

async function selectProjects(projects, flags, palette) {
  const requested = flag(flags, "project", null);
  const scannable = projects.filter((project) => !project.isWorkspaceRoot);
  const pool = scannable.length ? scannable : projects;

  if (requested === "all") return pool;
  if (requested) {
    const match = pool.find((project) => project.name === requested || project.relative === requested
      || project.relative === requested.replace(/^\.\//, ""));
    if (!match) {
      throw new Error(`no project named "${requested}". Run "tripwire list" to see the options.`);
    }
    return [match];
  }
  if (pool.length === 1) return pool;

  if (!process.stdin.isTTY) {
    process.stderr.write(`tripwire: ${pool.length} projects detected and no TTY for the picker — scanning all. Pass --project to narrow.\n`);
    return pool;
  }

  write("");
  write(`  ${palette.bold(`${pool.length} projects detected.`)} Which should Tripwire scan?`);
  write("");
  const numbered = [];
  for (const group of groupByStack(pool)) {
    write(`  ${palette.dim(group.stack)}`);
    for (const project of group.projects) {
      numbered.push(project);
      write(`    ${palette.bold(String(numbered.length).padStart(2))}. ${project.name.padEnd(26)} ${palette.dim(project.relative)}`);
    }
  }
  write(`    ${palette.bold(" a")}. ${palette.cyan("all of them")}`);
  write("");

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question("  Choice: ")).trim().toLowerCase();
    if (answer === "a" || answer === "all") return pool;
    const picked = answer.split(/[,\s]+/).map((piece) => numbered[Number(piece) - 1]).filter(Boolean);
    if (!picked.length) throw new Error("no valid choice made");
    return picked;
  } finally {
    rl.close();
  }
}

async function runTriage(result, flags, root, palette) {
  if (flags["no-ai"]) return { used: false, reason: "disabled with --no-ai" };

  const resolved = resolveProvider({
    provider: flag(flags, "provider", null),
    model: flag(flags, "model", null),
    apiKey: flag(flags, "api-key", null),
    baseUrl: flag(flags, "base-url", null)
  });
  if (!resolved.available) return { used: false, reason: resolved.reason };

  // Never send the contents of a file any source flagged as holding a credential —
  // including an external secrets engine. Shipping a file to a third-party model in the
  // course of reporting that its contents leaked would be the tool causing the incident
  // it is describing.
  const secretFiles = new Set(result.findings
    .filter((finding) => finding.ruleId.startsWith("secrets/")
      || finding.ruleId === "external/secret"
      || finding.ruleId === "context/secret-in-agent-context")
    .map((finding) => finding.file));

  const cache = new Map();
  const readSource = async (relative) => {
    if (secretFiles.has(relative)) return null;
    if (cache.has(relative)) return cache.get(relative);
    let text = null;
    try {
      text = await readFile(path.join(root, relative), "utf8");
    } catch {
      text = null;
    }
    cache.set(relative, text);
    return text;
  };

  const budget = Number(flag(flags, "budget", 250)) || 250;
  let outcome;
  try {
    outcome = await triageFindings(result.findings, {
      resolved,
      readFile: readSource,
      budget,
      onProgress: ({ index, total }) => {
        if (!flags.json) process.stderr.write(`${palette.dim(`triaging ${index}/${total}…`)}\r`);
      }
    });
  } catch (error) {
    // Triage is additive. A missing optional SDK, a bad key, or an unreachable endpoint
    // must degrade the scan to pattern confidence — never take the whole run down.
    if (!flags.json) process.stderr.write(`${" ".repeat(40)}\r`);
    return { used: false, reason: error.message };
  }
  if (!flags.json) process.stderr.write(`${" ".repeat(40)}\r`);

  return {
    used: true,
    provider: resolved.id,
    label: resolved.label,
    model: resolved.config.model,
    ...outcome
  };
}

/**
 * Write scan artifacts.
 *
 * By default only the two that get read: the fix plan, and the machine-readable findings.
 * The Markdown report duplicates what the terminal already showed, and SARIF only matters
 * to a CI uploader — generating either by default is output nobody asked for. Both come
 * back with an explicit `--out`, which is also the only way anything lands in the
 * repository rather than the cache directory.
 */
async function writeArtifacts(result, meta, flags) {
  const requested = flag(flags, "out", null);
  const base = requested ? path.resolve(String(requested)) : artifactDirFor(result.project.directory);
  const full = Boolean(requested);
  await mkdir(base, { recursive: true });

  const files = [
    [path.join(base, "FIX_PLAN.md"), renderFixPlan(result, meta)],
    [path.join(base, "findings.json"), `${JSON.stringify({
      version: meta.version,
      scannedAt: meta.scannedAt,
      project: publicProject(result.project),
      summary: result.summary,
      stats: result.stats,
      scope: result.scope || { mode: "all" },
      gatedRules: result.gatedRules,
      engines: result.engines || null,
      audit: result.audit || null,
      triage: result.ai,
      findings: result.findings
    }, null, 2)}\n`]
  ];

  if (full) {
    files.push([path.join(base, "report.md"), renderReportMarkdown(result, meta)]);
    files.push([path.join(base, "tripwire.sarif"), `${JSON.stringify(renderSarif(result, meta), null, 2)}\n`]);
  }

  for (const [file, contents] of files) await writeFile(file, contents, "utf8");
  return { files: files.map(([file]) => file), base, inRepo: full };
}

async function verifyCommands(project) {
  if (!project || project.kind !== "node") return [];
  const packageJson = await readJson(path.join(project.directory, "package.json"));
  const scripts = packageJson?.scripts || {};
  return ["test", "lint", "typecheck", "build"]
    .filter((name) => typeof scripts[name] === "string")
    .map((name) => `npm run ${name}`);
}

function publicProject(project) {
  return {
    name: project.name,
    relative: project.relative,
    kind: project.kind,
    language: project.language,
    framework: project.framework,
    manifest: project.manifest,
    aiPackages: project.aiPackages,
    dbPackages: project.dbPackages
  };
}

function severityTag(severity, palette) {
  const paint = { critical: palette.red, high: palette.red, medium: palette.yellow, low: palette.gray }[severity];
  return paint(severity.slice(0, 4).padEnd(4));
}

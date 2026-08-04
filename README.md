# Tripwire

Tripwire scans a codebase for the things that hurt your users and the things that mislead your agents, then writes a fix plan a coding agent can execute.

It finds injection sinks, committed credentials, and unsafe web defaults — the usual scanner territory. It also finds a category most scanners have no concept of: **the ways a repository lies to the model reading it.** Prompt-injection surfaces, model output flowing into a shell, tool descriptions assembled from runtime data, doc blocks that disagree with their function signature, and `CLAUDE.md` files pointing at scripts that no longer exist.

Created by [Marc Lapointe](https://lapointelabs.com/about) at Lapointe Labs. No runtime dependencies beyond Node.js 20.1+.

## Quick start

```sh
npx @lapointelabs/tripwire scan
```

In a monorepo, Tripwire detects every project and asks which to scan, grouped by stack:

```
  4 projects detected. Which should Tripwire scan?

  TypeScript · Next.js
     1. storefront                  apps/storefront
  C# · ASP.NET Core (net8.0)
     2. Billing.Api                 services/billing
  Python · FastAPI
     3. ingest                      services/ingest
   a. all of them
```

Pick one, or `--project all` to skip the prompt in CI.

## Use it as an agent skill

Tripwire installs itself into whatever coding agents your repository already uses:

```sh
npx @lapointelabs/tripwire@latest skills install
```

It detects which harnesses are configured and writes only those:

| Harness | File |
| --- | --- |
| Claude Code, Claude in VS Code | `.claude/skills/tripwire/` (skill bundle) |
| Cursor | `.cursor/skills/tripwire/` (skill bundle) |
| GitHub Copilot, VS Code | `.github/instructions/tripwire.instructions.md` |
| Codex, Amp, Jules, Zed, and others | `AGENTS.md` |

`skills list` shows what was detected; `--harness claude,cursor` targets specific ones.
An existing `AGENTS.md` is appended to inside HTML comment markers, so your own
instructions survive and a reinstall replaces Tripwire's section in place rather than
stacking copies. A skill you wrote by hand is never overwritten without `--force`.

**Claude Code and Cursor get a skill bundle**, not a passive rule file:

```
.cursor/skills/tripwire/
├── SKILL.md                 # short: prerequisites, commands, when to escalate
└── references/
    ├── triage.md            # the full scan → triage → fix → verify loop
    └── rules.md             # every rule, generated from the live rule set
```

Only the frontmatter description sits in context by default. The body loads when the
skill is invoked, and the references load only if the agent needs them — so a full triage
workflow costs nothing until someone asks for one. Both declare
`disable-model-invocation: true`, matching the convention for scanner skills: they run
when you type `/tripwire` or ask for a scan, not ambiently on every turn.

The playbook ships inside the package rather than being fetched from a server. `@latest`
already resolves the current version, so the content stays current without a reinstall,
and it works offline, in air-gapped CI, and behind a proxy that blocks outbound fetches.

**Install it once for every project** rather than per repository:

```sh
npx @lapointelabs/tripwire@latest skills install --harness cursor --root ~
```

**Pin the invocation** when the package is a devDependency rather than fetched by `npx`:

```sh
npx @lapointelabs/tripwire@latest skills install --command "pnpm tripwire"
```

## Regression checks

`--scope changed` reports only findings in files you touched, compared against the
merge-base with your trunk branch plus anything uncommitted:

```sh
npx @lapointelabs/tripwire@latest scan --scope changed
npx @lapointelabs/tripwire@latest scan --scope changed --score   # just the number
```

Scope narrows what is **reported**, never what is analysed. Rules that need whole-project
context — unused exports, cross-file duplication, stale instruction references — still run
against the entire tree; you simply are not shown findings in code you did not write. Use
`--base <ref>` to pin the comparison point.

## Why this exists

Static analysis has a credibility problem: tools report a thousand pattern matches, developers learn the output is mostly noise, and the three findings that mattered get skimmed past with the rest. Tripwire is built around two commitments meant to fix that.

**Say what you did not check.** A rule that could not run is reported as gated, never as clean. If no database driver is in the manifest, the SQL rules are listed as skipped rather than silently passing. If no model triage ran, low-confidence findings are labelled as leads, not conclusions. A quiet report and a clean codebase should never look the same.

**Make uncertainty a first-class field.** Every finding carries a confidence level that flows into the score, the report, and the fix plan. Certain findings are stated plainly; uncertain ones say so, and are the ones sent for review.

## The two-layer engine

**Layer 1 — deterministic.** Runs with no API key. A lexical pass blanks comments and string bodies while preserving byte offsets, so rules match real code instead of their own examples in a docstring. Loop and function bodies are found by brace and indent matching, so "await inside a loop" means inside the body, not within twenty lines of a `for`.

**Layer 2 — your model, optional.** Uncertain findings are batched and sent to a model you choose, which confirms or refutes each one against the surrounding source. Refuted findings drop out of the score and move to their own section. High-confidence findings are never sent, so cost tracks ambiguity rather than repository size.

```sh
export ANTHROPIC_API_KEY=...
npx @lapointelabs/tripwire scan               # picks up the key automatically

npx @lapointelabs/tripwire scan --provider ollama --model qwen2.5-coder   # fully local
npx @lapointelabs/tripwire scan --no-ai                                   # pattern confidence only
```

`tripwire providers` shows what is configured. Anthropic, any OpenAI-compatible endpoint, and Ollama are supported; `--base-url` covers self-hosted and proxied gateways.

Files the deterministic pass flagged as containing a credential are never sent to any model.

## What it produces

Alongside the terminal scorecard, each scan writes four artifacts to `.tripwire/`:

| File | Purpose |
| --- | --- |
| `FIX_PLAN.md` | **The one to hand an agent.** One task per finding, ordered by severity, each with its own acceptance criteria. |
| `report.md` | The human read: findings, evidence, triage notes, and an explicit list of what was not covered. |
| `findings.json` | Machine-readable, including refuted findings and their reasons. |
| `tripwire.sarif` | SARIF 2.1.0 for GitHub code scanning. |

`FIX_PLAN.md` is written to be pasted into a coding agent and worked top to bottom. It opens with a protocol that closes the loopholes an agent reaches for under pressure — no suppression comments, no scanner-dodging renames, no blanket refactors, and no marking a credential fixed when only the line was deleted and the key was never rotated. Every task states what must be true when it is done:

```markdown
### 1. [ ] SQL built by string interpolation — `src/api.js:11`

> CRITICAL · injection/sql-interpolation · high confidence — the pattern is unambiguous

**Done when:**

- [ ] Every value that varies at runtime reaches the query as a bound parameter.
- [ ] Any dynamic identifier is validated against a hard-coded allow-list.
- [ ] No ignore comment, rule disable, or scanner-dodging rename was used.
```

Marking a task `[~] not applicable` with a reason is an explicitly correct outcome. An agent that reads a finding, decides it is wrong, and says why is doing the job — a plan that only permits "fixed" teaches agents to force changes into code that was already fine.

## Rule packs

`tripwire rules` lists all of them.

**Security** — SQL, command, and NoSQL injection; runtime code evaluation and unsafe deserialization; path traversal; raw HTML sinks; permissive CORS; disabled TLS verification; fast hashes on credentials; predictable randomness for secrets; unvalidated redirects; committed credentials across fourteen vendor token formats.

**Agent safety** — external data spliced into prompts without a data/instruction boundary; model output reaching a shell, query, or filesystem; tool descriptions assembled at runtime; disabled agent permission gates; secrets interpolated into prompt text; instruction-override phrasing committed into source or into a `CLAUDE.md`; doc blocks that disagree with their signature; comments contradicting the code beneath them; instruction files referencing paths and npm scripts that do not exist.

**Correctness, maintainability, performance** — silently discarded errors; monolith files; oversized functions; deep nesting; long parameter lists; unused exports; cross-file duplication; sequential awaits and linear lookups inside loops.

## Language support

| Stack | Detected via | Coverage |
| --- | --- | --- |
| JavaScript / TypeScript | `package.json` | Full |
| React, Next.js, Nuxt, Remix, Svelte, Vue, Angular, Astro, NestJS, Express, Fastify | dependency fingerprint | Full |
| C# / .NET | `*.csproj` | Full |
| Python | `pyproject.toml`, `requirements.txt` | Full |
| Go, Rust, Ruby, PHP, Java | `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`, `pom.xml` | Security and structure |

Framework detection gates rules rather than guessing. A project with no model SDK in its manifest does not get prompt-injection findings, and the report says so.

## CI

```yaml
- run: npx @lapointelabs/tripwire scan --project all --fail-on high --no-ai
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .tripwire/tripwire.sarif
```

`--fail-on` accepts `critical`, `high`, `medium`, or `low`. Without it, Tripwire always exits 0 — a scanner that breaks the build on day one gets removed from the build on day two.

## Options

```
tripwire scan [PATH]        Scan a project and write a report and a fix plan.
tripwire list [PATH]        List detected projects, grouped by stack.
tripwire explain RULE       Explain one rule, including its false positives.
tripwire playbook           Print the agent triage playbook.
tripwire skills install     Install Tripwire as a skill for your coding agents.
tripwire skills list        Show which agent harnesses were detected.
tripwire rules              List every rule.
tripwire providers          List model providers for the triage layer.

  --scope changed|all       Report only findings in changed files. Default: all.
  --base REF                Base for --scope changed. Default: merge-base with trunk.
  --score                   Print only the numeric score.
  --project NAME|PATH|all   Choose a project without the interactive picker.
  --only ID|CATEGORY        Run only these rules or categories (repeatable).
  --skip ID|CATEGORY        Skip these rules or categories (repeatable).
  --all                     Show every finding in the terminal, not a summary.
  --fail-on LEVEL           Exit non-zero at critical|high|medium|low.
  --out DIR                 Where to write artifacts. Default: <project>/.tripwire
  --json                    Print findings as JSON and write no files.
  --provider NAME           anthropic | openai | ollama.
  --model NAME              Model id.
  --api-key KEY             Overrides the environment variable.
  --base-url URL            For self-hosted or proxied endpoints.
  --budget N                Maximum findings to send for triage. Default: 250.
  --no-ai                   Skip triage and report pattern confidence only.
  --harness LIST            claude, cursor, copilot, agents. Default: detected.
  --force                   Overwrite a skill file Tripwire did not write.
```

`explain` is worth knowing about. It prints what a rule matches, why it matters, what
"done" looks like, **and the shapes that rule is known to get wrong** — so an agent
deciding whether a finding is a false positive has something concrete to check against
instead of guessing.

```sh
npx @lapointelabs/tripwire@latest explain structure/await-in-loop
```

## Scoring

A score out of 100, based on finding density per thousand lines so that large codebases are not penalised for being large. Severity, category, and confidence all weight the penalty. Two ceilings apply on top: a confirmed critical finding caps the score at 55, and a confirmed high caps it at 78 — a single committed credential should not be averaged away by ten thousand clean lines.

Bands: 90+ Healthy · 75–89 Good · 60–74 Needs work · 40–59 At risk · below 40 Critical.

## Limits

Tripwire reads source text; it does not run your program. It cannot see values that arrive at runtime, configuration applied at deploy time, or a framework's implicit protections. It does not do interprocedural dataflow — a tainted value laundered through three helper functions in three files will be missed.

**The absence of a finding is not evidence of the absence of a bug.** Tripwire is a fast, broad first pass that tells you what it checked and how sure it is. It is not a replacement for a security review of code that handles money, credentials, or personal data.

## License

MIT

# Security scan for Claude Code and Cursor

A security scan for Claude Code, Cursor, and coding agents. Tripwire finds injection sinks, committed credentials, unsafe web defaults, and the ways a repository lies to the model reading it — then writes a fix plan an agent can execute.

It covers the usual scanner territory and a category most scanners miss: **prompt-injection surfaces, model output flowing into a shell, tool descriptions assembled from runtime data, doc blocks that disagree with their function signature, and `CLAUDE.md` files pointing at scripts that no longer exist.**

Where a specialist tool is better — cross-file dataflow, credential verification, advisory databases, MCP and skill inspection — Tripwire [runs that tool](#external-engines) rather than reimplementing it, and reconciles its findings into one report, one score, and one fix plan.

Created by [Marc Lapointe](https://lapointelabs.com/about) at Lapointe Labs. Requires Node.js 20.1+.

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

`tripwire providers` shows what is configured. Supported:

| Provider | Key | SDK | Shape |
| --- | --- | --- | --- |
| `anthropic` | `ANTHROPIC_API_KEY` | `@anthropic-ai/sdk` | Chat endpoint |
| `openai` | `OPENAI_API_KEY` | `openai` | Chat endpoint (any OpenAI-compatible URL) |
| `cursor` | `CURSOR_API_KEY` | `@cursor/sdk` *(optional peer)* | Cloud agent |
| `ollama` | none | `ollama` | Local chat endpoint |

Every provider goes through its vendor's official SDK rather than hand-rolled HTTP. Model
APIs drift — parameters get removed, auth changes, new stop reasons appear — and an SDK
absorbs that in a version bump instead of a silent breakage this project has to chase. The
SDKs also own retry, backoff, and timeout handling. They are imported lazily, so a scan
that never triages pays none of the load cost.

**Cursor's SDK is an optional peer, not a dependency.** It currently pulls a high-severity
transitive advisory (`@connectrpc/connect-node` → `undici`, no fix available). Forcing that
on everyone who installs a security scanner would break `npm audit` in their CI, so it is
opt-in:

```sh
npm install @cursor/sdk
```

Without it, `--provider cursor` reports what to install and the scan continues on pattern
confidence rather than failing. `--base-url` covers self-hosted and proxied gateways.

**Cursor works differently from the others.** Its API launches agents; there is no chat
endpoint to post a prompt to. Each triage batch therefore runs as a **no-repo cloud
agent** — created with the prompt, polled until its run reaches a terminal state, then
read from `result`. No repository is attached, nothing is cloned, no branch or pull
request is created. Expect it to be slower per batch than a chat provider, so Tripwire
sends larger batches at lower concurrency and allows minutes rather than seconds.

Files the deterministic pass flagged as containing a credential are never sent to any model.

## External engines

Tripwire does not try to out-depth the specialists. For an advisory database, 800 secret
detectors, or a cross-file dataflow engine, a generalist scanner reimplementing the thing
badly is worse than no coverage at all — a shallow pass that reports nothing reads exactly
like a clean one.

So it runs them instead, and folds their output into one report:

```sh
npx @lapointelabs/tripwire@latest scan --engines           # every installed engine
npx @lapointelabs/tripwire@latest scan --engines semgrep,trufflehog
npx @lapointelabs/tripwire@latest engines                  # what is available, and what is missing
```

| Engine | Domain | What it adds that Tripwire cannot do |
| --- | --- | --- |
| **Opengrep** / **Semgrep** | Code | Interprocedural and cross-file dataflow — the gap named in [Limits](#limits) |
| **TruffleHog** | Secrets | **Verification.** Calls the issuer to ask whether the key is live |
| **Gitleaks** | Secrets | Offline detection, for air-gapped agents where verification is unwanted |
| **osv-scanner** | Dependencies | Every ecosystem's advisories from one binary and one database |
| **Snyk Code** | Code | Commercial SAST · BYOK, `SNYK_TOKEN` |
| **Snyk Agent Scan** | Agent surface | Inspects the MCP servers and skills your agent actually loads |
| **agnix** | Agent instructions | 440+ rules validating `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, hooks, MCP config |

`tripwire engines` prints the full inventory — including engines you have *not* installed
and what each would have covered — because the useful question is what is going unchecked.

**Nothing is bundled, downloaded, or auto-installed.** Tripwire runs binaries you already
have. Commercial engines authenticate with your key from your environment; Tripwire reads
no key file, writes no key, and proxies nothing through any service of ours.

### What the harness actually adds

Running these five tools by hand is five configs and five output formats. Tripwire's claim
is not that it types the commands for you:

**One finding model.** Every engine's severity and confidence is normalized onto the same
four levels and the same three confidence tiers, then scored by the same function. A
Semgrep rule tagged `LOW CONFIDENCE` and a Tripwire pattern match of low confidence weigh
the same, because they mean the same thing.

**Overlap is reconciled, not concatenated.** Two engines and a native rule landing on one
line collapse into a single finding — the most authoritative one — which then records who
else agreed:

```
      app.js:6
        Command string is assembled from a variable before reaching a shell.
        exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
        confirmed by Semgrep / Opengrep
    injection/command-execution
```

Authority is explicit: a **verified** credential outranks everything, a published advisory
outranks a pattern match, and a Tripwire rule with an `explain` entry listing its known
false positives outranks an external engine's uncertain guess. Independent agreement lifts
a low-confidence finding to medium — it is evidence, not proof, and it stops there.

**Uncertain external findings go through the same triage layer.** Semgrep emits most of
its rules at `error` level while marking them `LOW CONFIDENCE`; run raw, those land in your
report as settled fact. Here they are routed to the model pass like any other lead. High
confidence findings are never sent, and neither are secrets or advisories — see below.

**Provenance survives.** Every external finding carries its engine and that engine's own
rule id into the terminal output, `findings.json`, the SARIF upload, and the fix plan's
**Reported by** line. A finding nobody can trace is a finding nobody can argue with.

**Absence is reported.** Domains no engine covered are named, with what Tripwire's own
coverage of them amounts to:

```
  Engines: semgrep 4 · trufflehog 1*
  * authenticated with your own key from the environment
  2 duplicate findings collapsed where engines agreed on the same line.
  Dependencies had no engine — Tripwire's own coverage is supply-chain posture only,
  no advisory database.
```

### Secrets never reach a model

The triage layer sends uncertain findings to a model. Any file that *any* source — a
Tripwire rule, TruffleHog, or Gitleaks — flagged as holding a credential is excluded from
that entirely. Shipping a file to a third-party API in the course of reporting that its
contents leaked would make the tool the incident it is describing.

For the same reason, no engine's raw secret value reaches the report. Evidence is the
redacted form or the detector name; the value is never printed into a fix plan or a CI log.

### One config file

```json
{
  "engines": {
    "semgrep": { "config": "p/ci", "limit": 200 },
    "trufflehog": { "args": ["--exclude-paths", ".trufflehogignore"] },
    "gitleaks": false
  },
  "scan": { "engines": "auto", "failOn": "high" }
}
```

`tripwire.config.json` at the project root, or `.tripwire.json`. Every value has a working
default and the file is entirely optional. Unknown keys are reported rather than ignored —
a setting that silently does nothing is how people conclude a setting does not work.

### Air-gapped and CI

```sh
npx @lapointelabs/tripwire@latest scan --engines --offline
```

`--offline` refuses any engine that needs the network and disables credential verification,
so a secret reported under it was matched by shape rather than confirmed against its issuer
— and the report says exactly that. Engines are opt-in for the same reason `--audit` is: a
scanner that quietly makes network calls cannot be run on an air-gapped build agent.

**Tripwire never passes `--dangerously-run-mcp-servers`** to Snyk Agent Scan. That flag
executes every command in an MCP config, which is the correct way to inspect a live server
and an indefensible thing for a security scanner to do to you unasked. Repository config
paths are passed explicitly, so the tool inspects this project rather than sweeping your
home directory.

## Dependency vulnerabilities

Tripwire does not ship an advisory database. `--engines` prefers **osv-scanner** when it is
installed — one binary, every ecosystem. `--audit` is the no-install path: it runs the
auditor your ecosystem already maintains, which ships with the toolchain you already have.

```sh
npx @lapointelabs/tripwire@latest scan --audit
```

| Ecosystem | Command run | Needs installing |
| --- | --- | --- |
| npm / pnpm / yarn | `npm audit`, `pnpm audit`, `yarn npm audit` — chosen by lockfile | ships with the manager |
| .NET | `dotnet list package --vulnerable --include-transitive` | ships with the SDK |
| Python | `pip-audit` | `pip install pip-audit` |
| Go | `govulncheck -json ./...` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| Rust | `cargo audit --json` | `cargo install cargo-audit` |

**govulncheck findings carry reachability.** A vulnerable function you never call is
reported at low severity and labelled as such, while one your code actually reaches is
high — the distinction is the reason to run it rather than diff a lockfile. Rust
advisories are reported at high, and `cargo audit`'s informational warnings
(unmaintained, unsound) at low, so a crate that merely stopped being updated does not
drown the real advisory.

A missing auditor names the command that installs it, including when the binary exists
but the subcommand does not (`cargo` without `cargo-audit`).

It is opt-in because it is the only part of a scan that spawns a subprocess and reaches
the network — a scanner that quietly makes network calls cannot be run on an air-gapped
build agent. When it has not run, the report says so rather than leaving a clean-looking
silence. A missing tool, an unrestored .NET project, or an offline registry degrades to a
stated reason and never fails the scan.

## What it produces

Nothing is written into your repository. The terminal output is the primary read; artifacts
land in a cache directory outside the tree, and the scan prints the path:

| File | When | Purpose |
| --- | --- | --- |
| `FIX_PLAN.md` | always | **The one to hand an agent.** One task per finding, ordered by severity, each with its own acceptance criteria. |
| `findings.json` | always | Machine-readable, including refuted findings and their reasons. |
| `report.md` | `--out` | The long-form human read: evidence, triage notes, and what was not covered. |
| `tripwire.sarif` | `--out` | SARIF 2.1.0 for GitHub code scanning. |

Two files by default, because only two get read — the terminal already covers what
`report.md` says, and SARIF matters only to a CI uploader. `--out DIR` writes all four
wherever you point it, and is the only way anything lands inside the repository.

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

**Supply chain** — missing or uncommitted lockfiles; dependencies pinned to `*`/`latest` or to a movable git ref; unrestricted dependency install scripts; registries reached over plain HTTP or with certificate checks disabled; CI actions pinned to mutable tags rather than commit SHAs; NuGet feeds without package source mapping; unpinned Python requirements and `--extra-index-url` dependency-confusion exposure.

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

With engines, install the ones you want and pass `--engines` — the SARIF upload carries
each finding's originating engine and rule id in its properties, so a dashboard entry stays
traceable to the tool that raised it:

```yaml
- run: pipx install semgrep && brew install trufflehog osv-scanner
- run: npx @lapointelabs/tripwire scan --project all --engines --fail-on high --no-ai --out .tripwire
  env:
    SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}   # optional — unlocks cross-file analysis
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
tripwire engines            List external scan engines and what each one covers.

  --scope changed|all       Report only findings in changed files. Default: all.
  --base REF                Base for --scope changed. Default: merge-base with trunk.
  --score                   Print only the numeric score.
  --project NAME|PATH|all   Choose a project without the interactive picker.
  --only ID|CATEGORY        Run only these rules or categories (repeatable).
  --skip ID|CATEGORY        Skip these rules or categories (repeatable).
  --all                     Show every finding in the terminal, not a summary.
  --fail-on LEVEL           Exit non-zero at critical|high|medium|low.
  --out DIR                 Also write report.md and SARIF here. Default: a cache
                            directory outside the repository.
  --json                    Print findings as JSON and write no files.
  --provider NAME           anthropic | openai | cursor | ollama.
  --model NAME              Model id.
  --api-key KEY             Overrides the environment variable.
  --base-url URL            For self-hosted or proxied endpoints.
  --budget N                Maximum findings to send for triage. Default: 250.
  --no-ai                   Skip triage and report pattern confidence only.
  --engines [LIST]          Run external engines. Bare: auto (every installed one).
                            Also: all, none, or semgrep,trufflehog,osv-scanner…
  --offline                 Refuse engines needing the network; no secret verification.
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

Tripwire reads source text; it does not run your program. It cannot see values that arrive at runtime, configuration applied at deploy time, or a framework's implicit protections. Its own rules do not do interprocedural dataflow — a tainted value laundered through three helper functions in three files will be missed. That specific gap is why [Semgrep or Opengrep](#external-engines) is the first engine in the table; with `--engines` it is covered by a tool built for it, and the report says which.

**The absence of a finding is not evidence of the absence of a bug.** Tripwire is a fast, broad first pass that tells you what it checked and how sure it is. It is not a replacement for a security review of code that handles money, credentials, or personal data.

**Without engines, several domains are shallow by design** — fourteen token patterns and no verification for secrets, posture checks and no advisory database for dependencies, nothing at all for the MCP and skill surface. `tripwire engines` prints that inventory whether or not you run them, because knowing what went unchecked is the point.

## License

MIT

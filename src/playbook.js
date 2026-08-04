/**
 * The canonical triage playbook.
 *
 * It ships inside the package rather than being fetched over HTTP. `npx …@latest` already
 * resolves the newest version, so the content stays current without a reinstall, and it
 * additionally works offline, in air-gapped CI, and behind a proxy that blocks arbitrary
 * fetches. It is printed by `tripwire playbook`, and every installed skill points at that
 * command rather than embedding a copy that can go stale.
 */
export const PLAYBOOK = `# Tripwire triage playbook

You are running a scan → triage → fix → verify loop over a real codebase. Work the tree
directly. Do not commit, do not push, and do not open a pull request unless the user asks.

## 1. Scan

\`\`\`sh
npx @lapointelabs/tripwire@latest scan --scope changed
\`\`\`

Add \`--audit\` to also run the ecosystem's vulnerability auditor (npm, pnpm, dotnet,
pip-audit) and fold known advisories into the same report. It spawns a subprocess and
uses the network, so it is opt-in.

Add \`--project <name>\` in a monorepo when more than one project is detected. Drop
\`--scope changed\` for a full-codebase pass. If an \`ANTHROPIC_API_KEY\`, \`OPENAI_API_KEY\`,
or local Ollama is available, triage runs automatically and marks findings confirmed or
refuted; otherwise every finding carries only its pattern confidence.

The scan prints the path to a generated \`FIX_PLAN.md\`. Read that file — it holds one task
per finding with acceptance criteria already written. It is stored outside the repository,
so nothing is added to the working tree.

## 2. Order the work

Fix in severity order: critical, then high, then medium, then low. Within a severity,
prefer findings marked *confirmed* or *high confidence* — those are the ones where the
tool is sure, so they are the ones where a fix is most likely to be warranted.

Stop and tell the user immediately, before fixing anything else, if you see:

- \`secrets/committed-credential\` or \`context/secret-in-agent-context\` — the credential
  must be rotated by a human. Editing the file does not revoke the key.
- \`context/injection-in-agent-context\` — instruction-override text in a file agents load
  automatically. Check \`git log\` for when it appeared and who added it before removing it.

## 3. Triage each finding before changing anything

For every task, read the cited file around the cited line. Enough of the surrounding
function to know what the value is and where it comes from — not just the flagged line.

Then decide, and be willing to decide either way:

- **Real.** Apply the fix described in the task.
- **Not applicable.** The surrounding code already handles it: the value is parameterized,
  validated, escaped, constrained to an allow-list, or a constant no caller can influence.
  Mark the task \`[~]\` and write one sentence naming the mitigation.

A finding you correctly reject is a successful outcome. Static analysis matches patterns;
it cannot read intent. Roughly a fifth of medium-confidence findings and more of the
low-confidence ones are expected to be wrong, and forcing a change into code that was
already correct is worse than leaving it alone.

## 4. Fix

- Change only what the task describes. No drive-by refactors, no reformatting, no
  dependency upgrades, no fixing a different task's finding along the way.
- Match the conventions of the surrounding code — its naming, its error handling, its
  comment density.
- **Never suppress instead of fixing.** No ignore comments, no rule disables, no renaming
  a variable to dodge a pattern, no moving code into a file the scanner skips. If the
  finding is wrong, say so in the task; do not silence it.
- Satisfy the task's acceptance criteria. They are written to be checkable by reading the
  changed code.

## 5. Verify

After each task, or each small batch:

\`\`\`sh
npm test            # or the project's own test command
\`\`\`

A fix that breaks the suite is not a fix. Revert it and reconsider.

When the batch is done, re-scan and confirm the score moved in the right direction and
the rules you addressed are gone:

\`\`\`sh
npx @lapointelabs/tripwire@latest scan --scope changed
\`\`\`

New findings can appear from code you just wrote. That is the loop working — triage them
the same way.

## 6. Report

Tell the user plainly:

- How many findings you fixed, by severity.
- How many you marked not applicable, and why for each.
- Anything you could not resolve, and what is blocking it.
- Anything that needs a human: credential rotation, an architectural decision, a change
  whose blast radius you could not determine.

Do not claim a finding is fixed unless you verified it. If tests failed, say so and show
the output. If you skipped part of the plan, say which part and why.

## Understanding a rule

\`\`\`sh
npx @lapointelabs/tripwire@latest explain <rule-id>
\`\`\`

Prints what the rule looks for, why it matters, how to fix it, what "done" means, and the
known false-positive shapes for that rule. Use it whenever a finding is unclear, and
before deciding a finding is wrong.
`;

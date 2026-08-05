# Enterprise adoption

Tripwire is designed to compose evidence, not to become the sole security authority. Use a
deep SAST engine, a verified-secret scanner, and an advisory database for production gates;
use Tripwire to normalize the results, expose missing coverage, and create an agent-ready
remediation plan.

## Rollout policy

Start in report-only mode, review the initial findings, then record the accepted backlog:

```sh
tripwire scan --project all --engines --no-ai --out .tripwire
tripwire scan --project all --engines --no-ai --write-baseline .tripwire-baseline.json
```

Commit the baseline after review. On pull requests, gate only new high and critical issues:

```sh
tripwire scan --project all --engines --no-ai \
  --baseline .tripwire-baseline.json --fail-on-new high --out .tripwire
```

Track resolved findings in the report and periodically replace the baseline in a dedicated,
reviewed change. Do not update it automatically in the same job that evaluates a pull
request—that turns the policy into an always-green gate.

## Recommended evidence stack

- Semgrep/Opengrep or CodeQL for deep dataflow and language-specific analysis.
- TruffleHog for verified credentials, or Gitleaks where verification is prohibited.
- osv-scanner for dependency advisories.
- Cisco AI Defense Skill Scanner and agnix for agent skills and instruction files.
- Snyk Agent Scan where centralized MCP and developer-fleet inventory is required.

Import precomputed CodeQL or vendor SARIF with `--import-sarif`. This keeps database creation,
licensing, and language builds in their native workflow while preserving results in the
combined fix plan and report.

## Data boundaries

The native scan is local and reads source as text. External engines are opt-in. `--offline`
refuses engines declared as networked. Tripwire never passes Snyk's MCP-execution flag and
the Cisco skill integration uses local analyzers unless the operator adds cloud flags.

Model triage is optional. Files flagged as containing credentials are excluded from every
triage request, and secret evidence is redacted. Other uncertain findings include a bounded
source excerpt when triage is enabled, so organizations should select a provider and
retention policy appropriate for their code.

Engine `env` values in `tripwire.config.json` are literal child-process overrides, not a
secret store. Do not put tokens there; provide credentials through the CI environment.

## CI and evidence retention

Archive `findings.json`, `report.html`, and `tripwire.sarif` as build artifacts. The HTML
report is self-contained and makes coverage gaps visible; SARIF is the system-of-record
format for GitHub code scanning. Retention periods should follow the repository's security
evidence policy because filenames, snippets, rule ids, and vulnerability descriptions can
still reveal sensitive architecture even when credentials are redacted.

Pin Tripwire and external scanners to reviewed versions in CI. Pin GitHub Actions to commit
SHAs. Use a scheduled dependency update process so immutable pins receive security updates.

## Trust and limitations

Treat the numeric score as a prioritization aid, not a compliance control. Absence of a
finding is not proof of safety, low-confidence findings still require review, and model
triage is a judgment rather than verification. The bundled benchmark is a regression suite
maintained by this project; independent corpora and manual adjudication are required for
comparative claims.

# Security policy

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** flow for this repository. Do not open
a public issue containing exploit details, credentials, or a repository that cannot be
shared publicly.

Include the affected version, operating system and Node.js version, a minimal reproduction,
impact, and any proposed mitigation. For leaks, provide only a redacted value and rotate the
credential before reporting it.

The maintainer will acknowledge a complete report when practical, coordinate a fix and
disclosure window with the reporter, and credit the reporter unless anonymity is requested.
No response-time or bounty commitment is implied.

## Supported versions

Security fixes are released on the latest published version. Older prereleases and
development snapshots are not supported; upgrade before reporting an issue already fixed
on the default branch.

## Scope

Security boundaries include secret redaction, model-triage exclusions, command construction
for external engines, path containment, SARIF/JSON/HTML escaping, baseline integrity, and
release provenance. Scanner false positives and false negatives are welcome as ordinary
issues unless they enable a security-boundary bypass.

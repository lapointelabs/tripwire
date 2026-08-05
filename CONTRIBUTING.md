# Contributing

Tripwire welcomes focused issues and pull requests. By participating, you agree to follow
the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development

Requires Node.js 20.1 or newer.

```sh
npm ci
npm run check
npm test
npm run benchmark:ci
```

Keep the deterministic scan offline and reproducible. New network calls, subprocesses, or
model requests must be opt-in, report when they did not run, and preserve the native result
when they fail.

## Rules and benchmarks

Every rule change needs a positive test and a nearby safe counterpart. Add or update a
labeled benchmark case when the behavior belongs in the public regression promise. Do not
improve the score by deleting a difficult expectation; document a known limitation instead.

External-engine parsers should use a captured, redacted real output fixture. Preserve the
upstream engine and rule id, never include raw credentials, and treat malformed successful
output as a failed scan rather than a clean result.

## Pull requests

Keep changes narrow, explain security tradeoffs, and call out compatibility or output-schema
changes. Update the README and JSON schema when adding a user-facing option. Maintainers may
request a smaller change before reviewing a broad refactor.

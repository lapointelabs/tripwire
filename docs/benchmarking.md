# Benchmarking

`tripwire benchmark` measures deterministic native rules against a labeled corpus. The
bundled corpus is deliberately small and checked into the repository so every result can
be reproduced and reviewed in a pull request.

```sh
npm run benchmark
npm run benchmark:ci
```

The CI command requires 100% precision and recall on the bundled regression cases. That is
a regression promise about those cases, not an estimate of performance on arbitrary code.

## Corpus format

A corpus directory contains `manifest.json` and one or more project trees:

```json
{
  "schemaVersion": 1,
  "name": "Team security corpus",
  "version": "1.0.0",
  "cases": [{
    "id": "javascript-web",
    "path": "corpus/javascript-web",
    "only": ["security"],
    "expectations": [
      { "ruleId": "injection/sql-interpolation", "file": "src/api.js", "line": 12 }
    ]
  }]
}
```

Every active finding without a matching expectation is a false positive. Every expectation
without an exact rule/file/line match is a false negative. A case can set `lineTolerance`,
but exact locations are preferred because they catch broken source mapping.

Include a safe counterpart beside each risky form. A positive-only corpus can measure
recall, but its precision number is not meaningful.

Run another corpus by path:

```sh
tripwire benchmark ./security-corpus --out ./benchmark-results
```

For credible comparisons between tools, keep the corpus outside every scanner's repository,
freeze tool versions and configuration, publish the raw outputs, and have at least two
reviewers adjudicate disputed findings without knowing which scanner produced them.

import { matches } from "../source.js";
import {
  CS, JS, PY, contextAfter, contextBefore, evidenceOf, interpolationExpressions,
  interpreterFor, looksLikeSql, templateTag, untrustedNames, UNTRUSTED_NAME
} from "./helpers.js";

/** Tagged templates that parameterize their interpolations rather than splicing them. */
const SAFE_SQL_TAGS = /^(?:sql|SQL|Prisma\.sql|prisma\.\$queryRaw|prisma\.\$executeRaw|\$queryRaw|\$executeRaw|db\.sql|pgp\.as|gql)$/;
const UNSAFE_SQL_TAGS = /\$queryRawUnsafe|\$executeRawUnsafe/;

const SQL_CALL = /\b(?:query|execute|executeSql|raw|rawQuery|prepare|run|all|get|exec|Sql|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlInterpolated)\s*\($/;

export const injectionRules = [
  {
    id: "injection/sql-interpolation",
    category: "security",
    severity: "critical",
    title: "SQL built by string interpolation",
    why: "Interpolating a value into SQL text lets a caller change the shape of the query instead of just its data. One quote character in the wrong field turns a lookup into a dump of the whole table.",
    fix: "Pass the value as a bound parameter (`?`, `$1`, `@name`) and let the driver escape it. Where a query builder is available, use it; where dynamic identifiers are genuinely needed, validate them against an allow-list of known column names.",
    languages: [...JS, ...PY, ...CS, "go", "php", "ruby", "java"],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const literal of file.strings) {
        const expressions = interpolationExpressions(literal.value);
        const interpolated = expressions.length > 0 || literal.interpolated;
        if (!interpolated || !looksLikeSql(literal.value)) continue;

        const tag = literal.quote === "`" ? templateTag(file, literal) : null;
        if (tag && SAFE_SQL_TAGS.test(tag)) continue;

        // A Python string with `{name}` is only interpolated when it is an f-string.
        if (file.language === "python") {
          const prefix = file.text.slice(Math.max(0, literal.start - 3), literal.start);
          const isFormatted = /[fF][rRbB]?$/.test(prefix) || /^\s*\.format\s*\(/.test(contextAfter(file, literal.end, 12));
          if (!isFormatted) continue;
        }

        findings.push({
          line: literal.line,
          evidence: evidenceOf(file, literal.line),
          message: expressions.length
            ? `Query text splices \`${expressions.slice(0, 3).join("`, `")}\` directly into SQL.`
            : "Query text is built with an interpolated string.",
          confidence: /\b(?:table|column|order\s+by|schema)\b/i.test(literal.value) ? "medium" : "high"
        });
      }

      // String concatenation into a SQL literal: "SELECT ... WHERE id = " + id
      for (const { line, index } of matches(file, /["'`][^"'`\n]{0,200}?\b(?:select|insert into|update|delete from)\b[^"'`\n]{0,200}?["'`]\s*\+\s*[A-Za-z_$]/i, "text")) {
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "SQL text is concatenated with a variable.",
          confidence: "high",
          index
        });
      }

      for (const { line } of matches(file, UNSAFE_SQL_TAGS)) {
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "`$queryRawUnsafe` bypasses Prisma's parameterization entirely.",
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "injection/sql-concat-argument",
    category: "security",
    severity: "high",
    title: "Query argument assembled from a variable",
    why: "A query call whose argument is a variable built elsewhere hides whether the value was parameterized. In practice this is where interpolated SQL goes to hide from review.",
    fix: "Move the query text to a constant and pass user values as parameters, so the call site shows at a glance that nothing dynamic reaches the SQL string.",
    languages: [...JS, ...PY, ...CS],
    requires: "database",
    confidence: "low",
    scan(file) {
      const findings = [];
      const pattern = /\b(?:CommandText|commandText)\s*=\s*[^;\n]*\+/;
      for (const { line } of matches(file, pattern)) {
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "`CommandText` is assembled with concatenation.",
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "injection/command-execution",
    category: "security",
    severity: "critical",
    title: "Shell command built from a variable",
    why: "A shell interprets `;`, `|`, `$( )` and backticks before your program ever sees them. Any value that reaches a shell string can append a second command of the caller's choosing.",
    fix: "Use the argument-array form (`execFile`, `spawn` without `shell: true`, `subprocess.run([...], shell=False)`, `ProcessStartInfo.ArgumentList`) so arguments are passed to the process directly and never parsed by a shell.",
    languages: [...JS, ...PY, ...CS, "go", "ruby", "php"],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const shellCalls = [
        /\b(?:exec|execSync)\s*\(\s*[`"'][^`"']*\$\{/,
        /\b(?:exec|execSync)\s*\(\s*[^)]*?[`"'][^`"'\n]*["'`]\s*\+/,
        /\bos\.system\s*\(\s*(?:f["']|[^)]*\+)/,
        /\bsubprocess\.(?:run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True/,
        /\bProcess\.Start\s*\(\s*(?:\$?"[^"]*"\s*\+|\$")/,
        /\bArguments\s*=\s*(?:\$"|[^;\n]*\+)/
      ];
      const tainted = untrustedNames(file);
      for (const pattern of shellCalls) {
        for (const { line, index } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;

          // An explicitly named interpreter removes the only real ambiguity in this rule.
          // `cmd.exe /c`, `/bin/sh -c`, and `powershell -Command` parse their argument
          // string for metacharacters by definition, so an interpolation there is a shell
          // injection regardless of what the variable is called.
          const shell = interpreterFor(file, index);
          const evidence = evidenceOf(file, line);
          const named = [...tainted].find((name) => new RegExp(`\\b${name}\\b`).test(evidence));

          findings.push({
            line,
            evidence,
            message: shell
              ? `Interpolated into an argument string passed to \`${shell}\`, which parses it for shell metacharacters.${named ? ` \`${named}\` is bound from the request.` : ""}`
              : `Command string is assembled from a variable before reaching a shell.${named ? ` \`${named}\` is bound from the request.` : ""}`,
            confidence: shell || named || UNTRUSTED_NAME.test(evidence) ? "high" : "medium"
          });
        }
      }
      for (const { line } of matches(file, /\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/)) {
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "`shell: true` reintroduces shell parsing for every argument.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "injection/dynamic-code-execution",
    category: "security",
    severity: "high",
    title: "Runtime code evaluation",
    why: "`eval` and its relatives compile whatever string they are handed. If any part of that string can be influenced from outside the process, the caller is choosing which code runs.",
    fix: "Replace it with an explicit dispatch table, `JSON.parse` for data, or a purpose-built parser. If the dynamic behaviour is genuinely required, restrict input to an allow-list before it reaches the evaluator.",
    languages: [...JS, ...PY, ...CS, "php", "ruby"],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      // Each pattern declares the languages it applies to. Without this, Python's bare
      // `exec(...)` matches Node's `child_process.exec`, double-reporting every shell
      // call that injection/command-execution already covers more precisely.
      const patterns = [
        [JS, /(?<![.\w])eval\s*\(/, "`eval` compiles its argument as code."],
        [JS, /\bnew\s+Function\s*\(/, "`new Function` compiles its argument as code."],
        [JS, /\bvm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(/, "`vm` executes its argument as code."],
        [JS, /\bsetTimeout\s*\(\s*["'`]/, "`setTimeout` with a string argument evaluates that string as code."],
        [PY, /(?<![.\w])eval\s*\(/, "`eval` compiles its argument as code."],
        [PY, /(?<![.\w])exec\s*\(\s*(?!["'`])/, "`exec` compiles its argument as code."],
        [PY, /\bpickle\.loads?\s*\(/, "`pickle` executes constructor code while deserializing."],
        [PY, /\byaml\.load\s*\((?![^)]*Safe)/, "`yaml.load` without `SafeLoader` can instantiate arbitrary Python objects."],
        [CS, /\bBinaryFormatter\b/, "`BinaryFormatter` deserialization is remotely exploitable and removed in modern .NET."],
        [CS, /\bJsonConvert\.DeserializeObject\s*<[^>]*>\s*\([^)]*TypeNameHandling/, "`TypeNameHandling` lets the payload choose which type to construct."],
        [["php", "ruby"], /(?<![.\w])eval\s*\(/, "`eval` compiles its argument as code."]
      ];
      for (const [languages, pattern, message] of patterns) {
        if (!languages.includes(file.language)) continue;
        for (const { line } of matches(file, pattern)) {
          if (findings.some((existing) => existing.line === line)) continue;
          const evidence = evidenceOf(file, line);
          findings.push({
            line,
            evidence,
            message,
            confidence: UNTRUSTED_NAME.test(evidence) ? "high" : "medium"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "injection/path-traversal",
    category: "security",
    severity: "high",
    title: "Filesystem path built from request data",
    why: "A path segment containing `../` walks out of the directory you intended to serve. The read succeeds, so nothing looks wrong until someone requests a config file.",
    fix: "Resolve the joined path, then confirm the result still sits inside the intended root before touching the filesystem. Reject the request rather than clamping the path.",
    languages: [...JS, ...PY, ...CS],
    requires: null,
    confidence: "low",
    scan(file) {
      const findings = [];
      const fsCall = /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|sendFile|open|File\.(?:ReadAll\w+|WriteAll\w+|Open|Delete))\s*\(/g;
      for (const { line, index } of matches(file, fsCall)) {
        const call = contextAfter(file, index, 220);
        if (!UNTRUSTED_NAME.test(call)) continue;
        // A guarded call resolves and re-checks the result; treat that as handled.
        const surrounding = file.text.slice(Math.max(0, index - 600), index + 220);
        if (/\b(?:startsWith|IsPathFullyQualified|relative\s*\(|normalize\s*\(|GetFullPath|safeJoin|resolveInside|realpath)\b/.test(surrounding)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Request-derived value reaches a filesystem call with no containment check.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "injection/nosql-operator",
    category: "security",
    severity: "high",
    title: "Request object passed straight into a query filter",
    why: "Passing a parsed body into a document query lets the caller supply operators rather than values. `{\"$ne\": null}` in a password field turns an authentication check into a match-anything query.",
    fix: "Read the specific fields you expect out of the request and build the filter from those primitives, or validate the body against a schema that rejects keys beginning with `$`.",
    languages: JS,
    requires: "database",
    confidence: "medium",
    scan(file) {
      const findings = [];
      const pattern = /\b(?:findOne|find|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:body|query|params))\b/;
      for (const { line } of matches(file, pattern)) {
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Request object is used directly as a query filter.",
          confidence: "high"
        });
      }
      return findings;
    }
  }
];

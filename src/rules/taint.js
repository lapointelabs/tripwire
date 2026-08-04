import path from "node:path";
import { matches } from "../source.js";
import { evidenceOf, untrustedNames } from "./helpers.js";
import { findFunctions } from "./structure.js";

/**
 * Reachability: does request-controlled data get from an entry point to a dangerous sink?
 *
 * Every other rule here reports a sink in isolation — "this line builds a shell command
 * from a variable". That is true and useful, and it is also how a real remote-code-execution
 * bug gets triaged as a low-priority nit: the sink usually lives in a helper that reads
 * like internal ops tooling, several files away from the HTTP route that reaches it.
 * Nobody reviewing the helper alone can tell whether an attacker controls the input.
 *
 * This rule does the join. It finds handler parameters the framework binds from the
 * request, follows one call hop into the file that receives them, and reports when that
 * file contains an execution sink — naming the route, the parameter, and the sink line so
 * the whole chain can be checked in one read.
 *
 * One hop, deliberately. Chasing an arbitrary call graph without types produces confident
 * nonsense; a single hop covers the common controller-calls-helper shape and is cheap to
 * verify by hand when it is wrong.
 */

const SINKS = [
  [/\bArguments\s*=\s*\$"/, "a shell argument string", "critical"],
  [/\bProcess\.Start\s*\(/, "a process launch", "critical"],
  [/\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(/, "a shell command", "critical"],
  [/\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen)\s*\(/, "a process launch", "critical"],
  [/(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(/, "a code evaluator", "critical"],
  [/\bCSharpScript\.\w+|\bScript\.RunAsync\b/, "a script evaluator", "critical"],
  [/\bAssembly\.Load\w*\s*\(|\bActivator\.CreateInstance\s*\(/, "runtime type loading", "high"],
  [/\bFromSqlRaw\s*\(|\bExecuteSqlRaw\w*\s*\(/, "a raw SQL execution", "high"],
  [/\bFile\.(?:WriteAll\w+|Delete)\s*\(|\bwriteFileSync?\s*\(/, "a filesystem write", "high"]
];

/** Framework entry points whose parameters arrive from the network. */
const ROUTE_ATTRIBUTE = /\[Http(?:Get|Post|Put|Patch|Delete)(?:\([^)]*\))?\]/;

function sinksIn(file) {
  const found = [];
  for (const [pattern, label, severity] of SINKS) {
    for (const { line } of matches(file, pattern, "text")) {
      found.push({ line, label, severity, evidence: evidenceOf(file, line) });
    }
  }
  return found.sort((a, b) => a.line - b.line);
}

/**
 * Files worth keeping for the cross-project pass: those holding a sink, and those binding
 * request data. Retaining only these keeps the union across a large solution small enough
 * to hold in memory while the analysis runs.
 */
export function relevantForTaint(file) {
  if (untrustedNames(file).size) return true;
  return SINKS.some(([pattern]) => pattern.test(file.text));
}

/**
 * Cross-project rules see every candidate file from every project in the run, not just
 * one project's. A layered .NET solution puts controllers in one assembly and the logic
 * they call in another, so a reachability join scoped to a single project is guaranteed
 * to miss exactly the chains worth finding.
 */
export const taintCrossProjectRules = [
  {
    id: "taint/request-reaches-execution-sink",
    category: "security",
    severity: "critical",
    title: "Request data reaches an execution sink",
    why: "A sink reviewed on its own looks like internal tooling; the same sink with an HTTP route wired to it is remote code execution. Reachability is the property that decides which one you have, and it is invisible from either file alone — which is why this shape survives review and lands in production.",
    fix: "Validate the value against an allow-list at the entry point before it travels — for a hostname, resolve it or match it against a strict pattern and reject anything else. Then remove the shell from the path entirely: pass arguments as an array so no interpreter parses them. Do both; either alone leaves the other as the only thing standing between a request and the host.",
    requires: null,
    confidence: "medium",
    aiTriage: true,
    async scanCross(context) {
      // Which files contain an execution sink, and what type does each file define?
      const sinkFiles = new Map();
      for (const file of context.files) {
        const found = sinksIn(file);
        if (found.length) sinkFiles.set(file.relative, { file, sinks: found });
      }
      if (!sinkFiles.size) return [];

      // C# convention puts one public type per file named after it, which makes the
      // receiver in `IcmpReachabilityChecker.ProbeAsync(host)` resolvable without types.
      const byTypeName = new Map();
      const byMethodName = new Map();
      for (const [relative, entry] of sinkFiles) {
        byTypeName.set(path.basename(relative).replace(/\.[^.]+$/, ""), entry);
        for (const found of findFunctions(entry.file)) {
          if (!byMethodName.has(found.name)) byMethodName.set(found.name, entry);
        }
      }

      const findings = [];
      for (const file of context.files) {
        const tainted = untrustedNames(file);
        if (!tainted.size) continue;

        const isRoute = ROUTE_ATTRIBUTE.test(file.text) || /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(/.test(file.code);
        // The class-level [Route(...)] prefix turns "GET reachability" into the actual
        // path someone can curl, which is the difference between a lead and a repro.
        const prefix = file.text.match(/\[Route\("([^"]*)"\)\]/)?.[1] || "";

        for (const handler of findFunctions(file)) {
          // Only parameters this handler itself binds from the request are attacker-
          // controlled here; a name tainted in another method says nothing about this one.
          const bound = [...tainted].filter((name) => new RegExp(`\\b${name}\\b`).test(handler.parameters));
          if (!bound.length) continue;

          const body = file.lines.slice(handler.startLine - 1, handler.endLine).join("\n");
          // Search by lines, including the handler's own start line. A byte window ending
          // at the start line misses the attribute whenever the signature match begins on
          // the preceding whitespace, which is most of the time.
          const header = file.lines.slice(Math.max(0, handler.startLine - 7), handler.startLine + 1).join("\n");
          const route = header.match(/\[Http(\w+)(?:\("([^"]*)"\))?\]/);

          for (const match of body.matchAll(/\b(?:([A-Z][\w]*)\s*\.\s*)?([A-Za-z_]\w*)\s*\(([^;]{0,400}?)\)/g)) {
            const [, receiver, method, args] = match;
            const passes = bound.find((name) => new RegExp(`\\b${name}\\b`).test(args));
            if (!passes) continue;

            const target = (receiver && byTypeName.get(receiver)) || byMethodName.get(method);
            if (!target) continue;
            if (target.file.relative === file.relative) continue;

            const sink = target.sinks[0];
            const key = `${file.relative}:${handler.startLine}:${target.file.relative}`;
            if (findings.some((existing) => existing.key === key)) continue;

            const routePath = route
              ? [prefix, route[2] || ""].filter(Boolean).join("/").replace(/\/{2,}/g, "/")
              : null;
            const where = route
              ? `\`${route[1].toUpperCase()} /${routePath}\``
              : `\`${handler.name}\``;

            // findFunctions can begin its match on the whitespace before the modifiers,
            // which lands on the attribute above. Point at the signature itself.
            const signatureLine = file.lines.findIndex((text, offset) =>
              offset >= handler.startLine - 2 && new RegExp(`\\b${handler.name}\\s*\\(`).test(text)) + 1;

            findings.push({
              key,
              file: file.relative,
              line: signatureLine > 0 ? signatureLine : handler.startLine,
              severity: sink.severity,
              evidence: `${handler.name}(${handler.parameters.replace(/\s+/g, " ").trim().slice(0, 90)})`,
              message: `${where} binds \`${passes}\` from the request and passes it to \`${receiver ? `${receiver}.` : ""}${method}\`, whose file reaches ${sink.label} at ${target.file.relative}:${sink.line}.`,
              confidence: isRoute ? "high" : "medium"
            });
          }
        }
      }

      return findings.map(({ key, ...finding }) => finding).slice(0, 25);
    }
  }
];

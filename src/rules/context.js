import path from "node:path";
import { matches } from "../source.js";
import { exists, readText } from "../util.js";
import { evidenceOf, isPlaceholder } from "./helpers.js";
import { INJECTION_PHRASES } from "./llm.js";

/**
 * The agent-context pack. Everything here is about a single failure mode: a coding
 * agent reads this repository as ground truth, and text that disagrees with the code
 * sends it confidently in the wrong direction. A human skims past a stale comment; a
 * model treats it as a specification.
 */

const SIGNATURE = /(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?\(([^)]*)\)\s*=>|(?:public|private|protected|internal|static|async|export|default|\s)*\b([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::[^{;]+)?\{)/;

export const contextRules = [
  {
    id: "context/stale-doc-parameter",
    category: "agent-safety",
    severity: "medium",
    title: "Documented parameter is not in the signature",
    why: "A doc block naming parameters the function does not take is a specification that disagrees with the code. An agent asked to call or extend the function will follow the doc block, because that is what the doc block is for, and produce calls that fail.",
    fix: "Update the doc block to match the current signature, or delete it. A wrong doc block is worse than none — it converts a lookup into a confident mistake.",
    languages: ["javascript", "typescript", "python", "csharp", "java"],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const comment of file.comments) {
        if (comment.kind === "line") continue;
        const documented = [
          ...[...comment.text.matchAll(/@param\s+(?:\{[^}]*\}\s+)?\[?([A-Za-z_$][\w$]*)/g)].map((match) => match[1]),
          ...[...comment.text.matchAll(/:param\s+(?:[\w\[\], ]+\s+)?([A-Za-z_$][\w$]*)\s*:/g)].map((match) => match[1]),
          ...[...comment.text.matchAll(/<param\s+name="([^"]+)"/g)].map((match) => match[1])
        ];
        if (!documented.length) continue;

        const signature = signatureNear(file, comment);
        if (!signature) continue;
        const declared = new Set(parameterNames(signature.parameters));
        // A destructured object parameter documents its members; those are legitimate.
        if (/[{[]/.test(signature.parameters)) continue;
        const missing = documented.filter((name) => !declared.has(name));
        if (!missing.length || missing.length === documented.length && declared.size === 0) continue;

        findings.push({
          line: comment.line,
          evidence: `${signature.name || "function"}(${signature.parameters.trim()})`,
          message: `Doc block documents \`${missing.join("`, `")}\`, which ${missing.length === 1 ? "is" : "are"} not in the signature.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "context/commented-out-code",
    category: "agent-safety",
    severity: "low",
    title: "Block of commented-out code",
    why: "Commented-out code reads as an alternative implementation that someone deliberately preserved. An agent asked to fix behaviour nearby will often restore it, on the reasonable assumption that it was kept for a reason.",
    fix: "Delete it. Version control already has it, and the commit that removed it explains more than the comment does.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const lineComments = file.comments.filter((comment) => comment.kind === "line");
      let run = [];
      const flush = () => {
        if (run.length >= 5) {
          const codeLike = run.filter((comment) => looksLikeCode(comment.text)).length;
          if (codeLike / run.length >= 0.6) {
            findings.push({
              line: run[0].line,
              endLine: run[run.length - 1].line,
              evidence: evidenceOf(file, run[0].line),
              message: `${run.length} consecutive commented-out source lines.`,
              confidence: "high"
            });
          }
        }
        run = [];
      };
      for (const comment of lineComments) {
        if (run.length && comment.line !== run[run.length - 1].line + 1) flush();
        run.push(comment);
      }
      flush();
      return findings;
    }
  },

  {
    id: "context/contradicted-comment",
    category: "agent-safety",
    severity: "medium",
    title: "Comment contradicts the code beneath it",
    why: "When prose and code disagree, a reader has to decide which one is lying. Models resolve that ambiguity toward the prose, because prose states intent and code only states behaviour — so a stale comment quietly becomes the spec.",
    fix: "Make the comment describe what the code does now, or remove it. Where the comment describes intent the code fails to meet, that gap is the actual bug.",
    languages: "*",
    requires: null,
    confidence: "low",
    aiTriage: true,
    scan(file) {
      const findings = [];
      for (const comment of file.comments) {
        if (comment.text.length < 12) continue;
        const body = bodyAfter(file, comment, 40);
        if (!body) continue;

        // Documented return value on a function that never returns one.
        if (/@returns?\b|:return:|<returns>/.test(comment.text) && !/(?:^|\n)\s*(?:return|yield)\s+\S/.test(body)) {
          if (!/\bvoid\b|@returns?\s*\{?\s*(?:void|None|undefined)/i.test(comment.text)) {
            findings.push({
              line: comment.line,
              evidence: comment.text.split("\n").find((piece) => /@returns?|:return:|<returns>/.test(piece))?.trim().slice(0, 140) || comment.text.slice(0, 140),
              message: "Doc block promises a return value; the body never returns one.",
              confidence: "medium"
            });
            continue;
          }
        }

        // Claims of purity, immutability, or no side effects next to obvious mutation.
        if (/\b(?:does not|doesn't|never)\b[^.]{0,40}\b(?:mutate|modify|change|write|persist)\b/i.test(comment.text)
          && /(?:^|\n)\s*(?:this\.)?[\w.$\[\]]+\s*(?:=|\.push\(|\.splice\(|\.pop\()/.test(body)) {
          findings.push({
            line: comment.line,
            evidence: comment.text.slice(0, 140),
            message: "Comment claims the code does not mutate state; the body assigns or pushes.",
            confidence: "medium"
          });
          continue;
        }

        // Safety claims that the code does not back up.
        if (/\b(?:safe|sanitiz|escap|validat)\w*\b[^.]{0,60}\b(?:input|user|param|value)\b/i.test(comment.text)
          && /\b(?:exec|eval|query|innerHTML|FromSqlRaw|os\.system)\b/.test(body)
          && !/\b(?:sanitiz|escap|validate|allowlist|whitelist|parameteri)\w*/i.test(body)) {
          findings.push({
            line: comment.line,
            evidence: comment.text.slice(0, 140),
            message: "Comment asserts the input is sanitized; no sanitization appears before the sink.",
            confidence: "medium"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "context/misdirecting-marker",
    category: "agent-safety",
    severity: "low",
    title: "Directive comment an agent will obey",
    why: "Comments addressed to a future reader — do not edit, deprecated, always use X — are read by agents as constraints on the change they were asked to make. When they are stale, they block correct edits or steer toward a path that no longer exists.",
    fix: "Give the directive an owner and a reason, or delete it. `// deprecated — use createSession, removal tracked in #482` survives review; `// don't touch` does not.",
    languages: "*",
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const directive = /\b(?:do not (?:edit|modify|change|touch)|don't (?:edit|modify|touch)|deprecated|obsolete|legacy[- ]only|always use|never use|must not be changed|hands off|auto-?generated)\b/i;
      for (const comment of file.comments) {
        if (!directive.test(comment.text)) continue;
        // A directive that explains itself is doing its job.
        if (/\b(?:because|since|instead use|use\s+`?[A-Za-z_$][\w$]*`?\s+instead|see\s+\S+|#\d+|https?:\/\/)/i.test(comment.text)) continue;
        findings.push({
          line: comment.line,
          evidence: comment.text.slice(0, 140),
          message: "Directive comment with no reason or replacement given.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "context/debt-marker",
    category: "maintainability",
    severity: "low",
    title: "Unowned TODO or FIXME",
    why: "A marker with no owner and no ticket is a note to nobody. It survives long enough that the surrounding code changes underneath it, at which point it starts describing a problem that no longer exists.",
    fix: "Attach an owner and an issue reference, or resolve it. Markers that cannot justify either are usually finished work nobody deleted.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const comment of file.comments) {
        const match = comment.text.match(/\b(TODO|FIXME|HACK|XXX|BUG|REFACTOR)\b[:\s]/);
        if (!match) continue;
        if (/@[A-Za-z][\w-]*|#\d+|[A-Z]+-\d+|https?:\/\//.test(comment.text)) continue;
        findings.push({
          line: comment.line,
          evidence: comment.text.slice(0, 140),
          message: `${match[1]} with no owner or issue reference.`,
          confidence: "high"
        });
      }
      return findings;
    }
  }
];

/**
 * Rules that need the whole project rather than one file. These run once per scanned
 * project and receive the file list plus resolved manifest data.
 */
export const contextProjectRules = [
  {
    id: "context/stale-instruction-reference",
    category: "agent-safety",
    severity: "high",
    title: "Agent instruction file points at something that does not exist",
    why: "Instruction files are loaded into context on every run, so a wrong path or a removed script is not a one-time mistake — it is a wrong premise the agent starts from every single time, and it will confidently build on it.",
    fix: "Correct the paths and script names, or remove the lines. Instruction files earn their keep only while they are accurate; a stale one is a liability that costs tokens on every request.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const findings = [];
      for (const agentFile of context.agentFiles) {
        const text = await readText(agentFile.absolute);
        if (!text) continue;
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index];
          for (const reference of referencedPaths(line)) {
            if (context.knownPaths.has(reference)) continue;
            if (await exists(path.join(context.root, reference))) continue;
            findings.push({
              file: agentFile.relative,
              line: index + 1,
              evidence: line.trim().slice(0, 160),
              message: `References \`${reference}\`, which does not exist in the repository.`,
              confidence: "high"
            });
          }
          for (const script of referencedScripts(line)) {
            if (context.scripts.has(script)) continue;
            findings.push({
              file: agentFile.relative,
              line: index + 1,
              evidence: line.trim().slice(0, 160),
              message: `References the script \`${script}\`, which is not defined in package.json.`,
              confidence: "high"
            });
          }
        }
      }
      return findings;
    }
  },

  {
    id: "context/secret-in-agent-context",
    category: "security",
    severity: "critical",
    title: "Credential inside an agent instruction file",
    why: "Instruction files are uploaded to a model provider on every request. A secret here is not merely committed — it is actively transmitted to a third party, repeatedly, and retained in whatever conversation logs they keep.",
    fix: "Rotate the credential immediately, then remove it. Reference the environment variable by name if the agent needs to know it exists.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const findings = [];
      const pattern = /\b([\w.]*(?:password|secret|token|api[_-]?key|apikey|access[_-]?key|credential))\s*[:=]\s*["'`]?([^\s"'`,]{8,})/i;
      for (const agentFile of context.agentFiles) {
        const text = await readText(agentFile.absolute);
        if (!text) continue;
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length; index += 1) {
          const match = lines[index].match(pattern);
          if (!match || isPlaceholder(match[2])) continue;
          findings.push({
            file: agentFile.relative,
            line: index + 1,
            evidence: lines[index].trim().slice(0, 60).replace(match[2], `${match[2].slice(0, 4)}********`),
            message: `\`${match[1]}\` has a concrete value in a file sent to the model on every run.`,
            confidence: "high"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "context/injection-in-agent-context",
    category: "agent-safety",
    severity: "critical",
    title: "Instruction-override text in an agent context file",
    why: "This is the highest-value place to plant a prompt injection, because the content is loaded automatically, trusted implicitly, and rarely re-read by anyone. A line added here runs on every agent invocation in the repository.",
    fix: "Treat this as a supply-chain event, not a style issue: find the commit that introduced the line, confirm who authored it, and remove it.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      const findings = [];
      for (const agentFile of context.agentFiles) {
        const text = await readText(agentFile.absolute);
        if (!text) continue;
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length; index += 1) {
          const match = lines[index].match(INJECTION_PHRASES);
          if (!match) continue;
          findings.push({
            file: agentFile.relative,
            line: index + 1,
            evidence: lines[index].trim().slice(0, 160),
            message: `Instruction-override phrasing in a file the agent loads automatically: "${match[0].slice(0, 60)}".`,
            confidence: "high"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "context/missing-agent-instructions",
    category: "agent-safety",
    severity: "low",
    title: "No agent instruction file",
    why: "Without one, every agent session rediscovers the build commands, the test runner, and the conventions from scratch — differently each time, and sometimes wrongly.",
    fix: "Add a short CLAUDE.md or AGENTS.md covering how to build, how to test, and the two or three conventions a newcomer gets wrong. Keep it under a page; long ones go stale and stop being read carefully.",
    requires: null,
    confidence: "high",
    async scanProject(context) {
      if (context.agentFiles.length) return [];
      if (context.files.length < 15) return [];
      return [{
        file: context.projectRelative === "." ? "." : context.projectRelative,
        line: 1,
        evidence: `${context.files.length} source files, no CLAUDE.md or AGENTS.md`,
        message: "Repository has no agent instruction file.",
        confidence: "high"
      }];
    }
  }
];

function signatureNear(file, comment) {
  // JSDoc and XML doc comments precede the declaration; Python docstrings follow it.
  const forward = file.text.slice(comment.end, comment.end + 400);
  const backward = file.text.slice(Math.max(0, comment.start - 400), comment.start);
  const source = comment.kind === "doc" ? backward.split(/\r?\n/).reverse().join("\n") : forward;
  const python = source.match(/def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
  if (comment.kind === "doc") return python ? { name: python[1], parameters: python[2] } : null;
  const match = forward.match(SIGNATURE);
  if (!match) return python ? { name: python[1], parameters: python[2] } : null;
  const name = match[1] || match[3] || match[5];
  const parameters = match[2] ?? match[4] ?? match[6] ?? "";
  return { name, parameters };
}

function parameterNames(parameters) {
  return parameters
    .split(",")
    .map((piece) => piece.trim())
    .filter(Boolean)
    .map((piece) => piece.replace(/^\*+|^&/, "").split(/[:=]/)[0].trim())
    .map((piece) => piece.split(/\s+/).pop())
    .filter((piece) => /^[A-Za-z_$][\w$]*$/.test(piece));
}

function bodyAfter(file, comment, lineCount) {
  const startLine = comment.line + countLines(comment.text);
  const slice = file.lines.slice(startLine - 1, startLine - 1 + lineCount);
  return slice.join("\n");
}

function countLines(text) {
  return text.split("\n").length;
}

function looksLikeCode(text) {
  if (!text) return false;
  if (/^[-*#=]{3,}$/.test(text)) return false;
  const codeSignals = /[;{}]\s*$|^\s*(?:if|for|while|return|const|let|var|def|class|import|from|public|private|function|await|async|else|catch|try)\b|=>|\w+\s*\([^)]*\)\s*[;{]?$|^\s*[\w.]+\s*=[^=]/;
  const proseSignals = /^[A-Z][^=;{}()]{20,}[.!?]$|\b(?:see|note|this|the|we|because|todo|fixme)\b.*\b(?:is|are|was|should|will)\b/i;
  return codeSignals.test(text) && !proseSignals.test(text);
}

function referencedPaths(line) {
  const found = new Set();
  for (const match of line.matchAll(/`([^`\n]+)`/g)) {
    const candidate = match[1].trim();
    if (!/^[\w./@-]+$/.test(candidate)) continue;
    if (/^https?:/.test(candidate) || candidate.startsWith("-")) continue;
    if (/[*?]/.test(candidate)) continue;

    // A slash alone does not make something a path. Instruction files are full of
    // `word/word` tokens that are not files: slash commands (`/tripwire`), rule and
    // policy identifiers (`secrets/committed-credential`), branch names, and scoped
    // package names. Requiring a file extension, a `./` prefix, or a trailing slash
    // keeps the real references and drops the rest — a missed path is a far cheaper
    // mistake here than flagging every instruction file that names a convention.
    const hasExtension = /\.\w{1,5}$/.test(candidate);
    const isExplicitlyRelative = candidate.startsWith("./");
    const isDirectory = candidate.endsWith("/");
    if (!hasExtension && !isExplicitlyRelative && !isDirectory) continue;
    if (candidate.startsWith("/")) continue;

    found.add(candidate.replace(/^\.\//, "").replace(/\/$/, ""));
  }
  return [...found];
}

function referencedScripts(line) {
  const found = new Set();
  for (const match of line.matchAll(/\b(?:npm|pnpm|yarn|bun)\s+run\s+([\w:-]+)/g)) found.add(match[1]);
  return [...found];
}

import { createHash } from "node:crypto";
import { matches } from "../source.js";
import { evidenceOf, indentWidth } from "./helpers.js";

const FILE_THRESHOLDS = { medium: 400, high: 800, critical: 1600 };
const FUNCTION_THRESHOLDS = { medium: 60, high: 120, critical: 250 };

export const structureRules = [
  {
    id: "structure/monolith-file",
    category: "maintainability",
    severity: "medium",
    title: "File is large enough to resist review",
    why: "Past a few hundred lines a file stops fitting in one reading. For an agent the cost is concrete: editing it means reading all of it, which crowds out the rest of the task, and edits get made without seeing the parts that matter.",
    fix: "Split along the seams already in the file — the groups of functions that share state, and the ones that do not. The goal is files a reader can hold at once, not a target line count.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const count = file.lines.length;
      if (count <= FILE_THRESHOLDS.medium) return [];
      if (file.language === "markdown" || file.language === "json") return [];
      const severity = count > FILE_THRESHOLDS.critical ? "high"
        : count > FILE_THRESHOLDS.high ? "medium" : "low";
      return [{
        line: 1,
        endLine: count,
        severity,
        evidence: `${count} lines`,
        message: `${count} lines in a single file.`,
        confidence: "high"
      }];
    }
  },

  {
    id: "structure/oversized-function",
    category: "maintainability",
    severity: "medium",
    title: "Function is too long to hold in mind",
    why: "A long function hides the branch you did not read. Both people and models modify what they can see and miss the early return two hundred lines up that makes the change wrong.",
    fix: "Extract the distinct phases into named functions. The names are the point: they turn a block of steps into a sequence a reader can check without reading each step.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const found of findFunctions(file)) {
        const length = found.endLine - found.startLine + 1;
        if (length <= FUNCTION_THRESHOLDS.medium) continue;
        const severity = length > FUNCTION_THRESHOLDS.critical ? "high"
          : length > FUNCTION_THRESHOLDS.high ? "medium" : "low";
        findings.push({
          line: found.startLine,
          endLine: found.endLine,
          severity,
          evidence: `${found.name}() — ${length} lines`,
          message: `\`${found.name}\` is ${length} lines long.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "structure/deep-nesting",
    category: "maintainability",
    severity: "low",
    title: "Deeply nested control flow",
    why: "Every level of nesting is a condition the reader has to keep true while reading everything inside it. Past four or five, tracking which branch you are in costs more attention than the logic itself.",
    fix: "Invert the guards and return early, or extract the inner block. Both flatten the shape; early returns usually read better because they put the exceptional cases first and leave the main path unindented.",
    languages: "*",
    requires: null,
    confidence: "medium",
    scan(file) {
      if (file.language === "markdown" || file.language === "yaml" || file.language === "json") return [];
      const findings = [];
      const unit = file.language === "python" ? 4 : 2;
      const threshold = unit * 6;
      let reported = -10;
      for (let index = 0; index < file.lines.length; index += 1) {
        const text = file.lines[index];
        if (!text.trim() || !/\b(?:if|for|while|switch|try|foreach|else)\b/.test(text)) continue;
        const depth = indentWidth(text);
        if (depth < threshold) continue;
        if (index - reported < 20) continue;
        reported = index;
        findings.push({
          line: index + 1,
          evidence: evidenceOf(file, index + 1),
          message: `Control flow nested roughly ${Math.floor(depth / unit)} levels deep.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "structure/long-parameter-list",
    category: "maintainability",
    severity: "low",
    title: "Function takes too many positional parameters",
    why: "Long positional lists are called wrongly. Two adjacent parameters of the same type will eventually be swapped at a call site, and the type checker will not notice.",
    fix: "Group related parameters into an options object or a small named type, so call sites read as labelled fields rather than an ordered list.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const found of findFunctions(file)) {
        const parameters = splitParameters(found.parameters);
        if (parameters.length <= 6) continue;
        findings.push({
          line: found.startLine,
          evidence: `${found.name}(${parameters.length} parameters)`,
          message: `\`${found.name}\` takes ${parameters.length} positional parameters.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "structure/silenced-error",
    category: "correctness",
    severity: "medium",
    title: "Error caught and discarded",
    why: "An empty catch converts a failure into a wrong result that keeps going. The symptom shows up somewhere unrelated later, with nothing in the logs connecting it back here.",
    fix: "Handle it, log it with enough context to identify the call, or let it propagate. If the error is genuinely expected, say which one and why in a comment — that is a different thing from swallowing everything.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const patterns = [
        /catch\s*(?:\([^)]*\))?\s*\{\s*\}/,
        /except[^\n:]*:\s*\n\s*pass\b/,
        /catch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\/[^\n]*\n\s*)*\}/
      ];
      for (const pattern of patterns) {
        for (const { line } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;
          // A comment explaining the intent is the documented exception.
          const window = file.text.slice(Math.max(0, (file.lineStarts[line - 1] ?? 0) - 200), (file.lineStarts[line + 2] ?? file.text.length));
          if (/\b(?:intentional|expected|best[- ]effort|optional|ignore[sd]? (?:on purpose|deliberately)|not fatal|continue searching|fall\s?back)\b/i.test(window)) continue;
          findings.push({
            line,
            evidence: evidenceOf(file, line),
            message: "Caught error is discarded without handling or logging.",
            confidence: "high"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "structure/await-in-loop",
    category: "performance",
    severity: "low",
    title: "Sequential awaits in a loop",
    why: "Each iteration waits for the previous one to finish. When the calls do not depend on each other, total latency is the sum of every round trip instead of the slowest one.",
    fix: "Collect the work and await it together with `Promise.all` / `asyncio.gather` / `Task.WhenAll`. Keep the loop where each iteration genuinely needs the previous result, or where you are deliberately rate-limiting.",
    languages: ["javascript", "typescript", "python", "csharp"],
    requires: null,
    confidence: "medium",
    scan(file) {
      const bodies = loopBodies(file);
      if (!bodies.length) return [];
      const findings = [];
      const concurrent = /\bawait\s+(?:Promise\.all|Promise\.allSettled|Promise\.race|Promise\.any|asyncio\.gather|Task\.WhenAll|Task\.WhenAny)/;
      for (const { line, index } of matches(file, /\bawait\s+/)) {
        // `for (const x of await readdir())` awaits once, in the loop *header* — the
        // header sits outside the body range, so scope containment excludes it.
        const body = bodies.find((candidate) => index > candidate.start && index < candidate.end);
        if (!body) continue;
        if (concurrent.test(file.lineText(line))) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `Awaited call runs once per iteration of the ${body.kind} at line ${body.line}, in sequence.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "structure/linear-lookup-in-loop",
    category: "performance",
    severity: "low",
    title: "Linear array lookup inside a loop",
    why: "`includes`, `indexOf`, and `find` scan the whole array each call. Inside a loop that is quadratic work, which is invisible on ten items and a hang on ten thousand.",
    fix: "Build a `Set` or `Map` once before the loop and look up against that. The setup cost is one pass; the savings are every pass after it.",
    languages: ["javascript", "typescript", "csharp", "java"],
    requires: null,
    confidence: "medium",
    scan(file) {
      const bodies = loopBodies(file);
      if (!bodies.length) return [];
      const findings = [];
      for (const { match, line, index } of matches(file, /\.(?:includes|indexOf|find|findIndex|Contains|IndexOf)\s*\(/)) {
        const body = bodies.find((candidate) => index > candidate.start && index < candidate.end);
        if (!body) continue;
        // `indexOf` on a string is a scan of one value, not a scan of a collection per item.
        const receiver = file.text.slice(Math.max(0, index - 40), index);
        if (/(?:buffer|string|str|text|line|content|name|path|url|message)\s*$/i.test(receiver)) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `\`${match[0].slice(1, -1).trim()}\` runs on every iteration of the ${body.kind} at line ${body.line}.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  }
];

export const structureProjectRules = [
  {
    id: "structure/unused-export",
    category: "maintainability",
    severity: "low",
    title: "Exported symbol nobody imports",
    why: "An export is a promise that something outside the file depends on this name. When nothing does, it widens the surface a reader has to treat as load-bearing and makes the symbol look more important than it is.",
    fix: "Drop the `export` keyword if the symbol is used locally, or delete it if it is not used at all.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      const exported = new Map();
      const imported = new Set();
      for (const file of context.preparedFiles) {
        if (!/^(?:javascript|typescript)$/.test(file.language)) continue;
        if (/(?:^|\/)(?:index|main)\.[jt]sx?$/.test(file.relative)) continue;
        for (const { match, line } of matches(file, /\bexport\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)/)) {
          exported.set(match[1], { file: file.relative, line, name: match[1] });
        }
        for (const { match } of matches(file, /\bimport\s+(?:type\s+)?\{([^}]*)\}/)) {
          for (const piece of match[1].split(",")) {
            const name = piece.trim().split(/\s+as\s+/)[0].trim();
            if (name) imported.add(name);
          }
        }
        for (const { match } of matches(file, /\bexport\s*\{([^}]*)\}/)) {
          for (const piece of match[1].split(",")) {
            const name = piece.trim().split(/\s+as\s+/)[0].trim();
            if (name) imported.add(name);
          }
        }
        for (const { match } of matches(file, /\brequire\s*\([^)]*\)\s*\.\s*([A-Za-z_$][\w$]*)/)) imported.add(match[1]);
      }
      const findings = [];
      for (const [name, record] of exported) {
        if (imported.has(name)) continue;
        // A name referenced by string anywhere (dynamic dispatch, DI container) is in use.
        if (context.symbolReferences.get(name) > 1) continue;
        findings.push({
          file: record.file,
          line: record.line,
          evidence: `export ${name}`,
          message: `\`${name}\` is exported but never imported anywhere in this project.`,
          confidence: "medium"
        });
      }
      return findings.slice(0, 40);
    }
  },

  {
    id: "structure/duplicated-block",
    category: "maintainability",
    severity: "low",
    title: "Block duplicated across files",
    why: "Duplicated logic drifts. The copies stay identical exactly long enough for everyone to stop checking, and then one of them gets the bug fix.",
    fix: "Extract the shared block once the copies have genuinely the same reason to change. Where they only look alike, leave them alone — premature extraction couples things that should move apart.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      const windowSize = 8;
      const seen = new Map();
      for (const file of context.preparedFiles) {
        if (file.language === "markdown" || file.language === "json" || file.language === "yaml") continue;
        const normalized = file.lines.map((line) => line.trim().replace(/\s+/g, " "));
        for (let index = 0; index + windowSize <= normalized.length; index += 1) {
          const slice = normalized.slice(index, index + windowSize);
          const substantive = slice.filter((line) => line.length > 12 && !/^[)}\];,]+$/.test(line));
          if (substantive.length < windowSize - 1) continue;
          const digest = createHash("sha1").update(slice.join("\n")).digest("hex");
          if (!seen.has(digest)) seen.set(digest, []);
          seen.get(digest).push({ file: file.relative, line: index + 1 });
        }
      }
      const findings = [];
      for (const occurrences of seen.values()) {
        if (occurrences.length < 2) continue;
        const distinctFiles = new Set(occurrences.map((entry) => entry.file));
        if (distinctFiles.size < 2) continue;
        const [first, ...rest] = occurrences;
        if (findings.some((existing) => existing.file === first.file && Math.abs(existing.line - first.line) < windowSize)) continue;
        findings.push({
          file: first.file,
          line: first.line,
          endLine: first.line + windowSize - 1,
          evidence: `${windowSize} identical lines`,
          message: `Also appears at ${rest.slice(0, 3).map((entry) => `${entry.file}:${entry.line}`).join(", ")}.`,
          confidence: "medium"
        });
      }
      return findings.slice(0, 25);
    }
  }
];

/**
 * Locate the *bodies* of loops, as offset ranges into the masked code view.
 *
 * Proximity heuristics ("within 20 lines of a `for`") are what make this class of rule
 * noisy: they flag the loop header itself, they flag code after the loop closed, and
 * they miss anything past the window. Matching the body braces costs little more and
 * gets containment exactly right — `for (const x of await readdir())` awaits in the
 * header, outside every body range, so it is correctly not a sequential await.
 */
export function loopBodies(file) {
  if (file.language === "python") return pythonLoopBodies(file);
  const bodies = [];
  const header = /\b(?:for|foreach|while)\s*\(|\.\s*(?:forEach|map|filter|flatMap|some|every)\s*\(/g;
  let match;
  while ((match = header.exec(file.code)) !== null) {
    const openParen = file.code.indexOf("(", match.index);
    if (openParen === -1) continue;
    const closeParen = matchDelimiter(file.code, openParen, "(", ")");
    if (closeParen === -1) continue;

    const isCallback = /forEach|map|filter|flatMap|some|every/.test(match[0]);
    // A `for (…)` header can itself contain braces — `{ recursive: true }` in an
    // argument, a destructured binding — so the body brace is the one *after* the
    // header's balanced closing paren, never simply the next `{` in the file.
    // A callback's body brace instead lives inside the parens, opened by its arrow.
    const open = isCallback
      ? findArrowBrace(file.code, openParen, closeParen)
      : nextBraceAfter(file.code, closeParen);
    if (open === -1) continue;

    const close = matchDelimiter(file.code, open, "{", "}");
    if (close === -1) continue;
    bodies.push({
      kind: isCallback ? "callback loop" : "loop",
      line: file.lineAt(match.index),
      start: open,
      end: close
    });
    header.lastIndex = open + 1;
  }
  return bodies;
}

/** The first `{` after a loop header's `)`, provided nothing but whitespace intervenes. */
function nextBraceAfter(code, closeParen) {
  for (let index = closeParen + 1; index < code.length; index += 1) {
    const char = code[index];
    if (char === "{") return index;
    if (!/\s/.test(char)) return -1; // single-statement body — no block to scope to
  }
  return -1;
}

/** The brace opening a callback body: the `{` immediately following `=>` inside the call. */
function findArrowBrace(code, openParen, closeParen) {
  const arrow = code.indexOf("=>", openParen);
  if (arrow === -1 || arrow > closeParen) return -1;
  for (let index = arrow + 2; index < closeParen; index += 1) {
    const char = code[index];
    if (char === "{") return index;
    if (!/\s/.test(char)) return -1; // concise arrow body — a single expression
  }
  return -1;
}

function matchDelimiter(code, open, openChar, closeChar) {
  let depth = 0;
  for (let index = open; index < code.length; index += 1) {
    if (code[index] === openChar) depth += 1;
    else if (code[index] === closeChar) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function pythonLoopBodies(file) {
  const bodies = [];
  for (let index = 0; index < file.lines.length; index += 1) {
    const match = file.lines[index].match(/^(\s*)(?:async\s+)?(for|while)\b.*:\s*$/);
    if (!match) continue;
    const baseIndent = indentWidth(match[1]);
    let end = index + 1;
    for (let cursor = index + 1; cursor < file.lines.length; cursor += 1) {
      if (!file.lines[cursor].trim()) continue;
      if (indentWidth(file.lines[cursor]) <= baseIndent) break;
      end = cursor;
    }
    if (end <= index) continue;
    bodies.push({
      kind: "loop",
      line: index + 1,
      start: file.lineStarts[index + 1] ?? 0,
      end: (file.lineStarts[end + 1] ?? file.text.length) - 1
    });
  }
  return bodies;
}

/**
 * Locate function bodies without a parser: brace matching over the masked code view for
 * C-like languages, indentation for Python. Both are approximations, but they operate on
 * text where strings and comments are already blanked, so braces inside a string literal
 * cannot throw off the count.
 */
export function findFunctions(file) {
  if (file.language === "python") return findPythonFunctions(file);
  const found = [];
  const declaration = /(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\)\s*(?:=>)?|(?:public|private|protected|internal|static|virtual|override|async|export|\s)+[\w<>,\[\]?]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\))\s*\{/g;
  let match;
  while ((match = declaration.exec(file.code)) !== null) {
    const name = match[1] || match[3] || match[5];
    const parameters = match[2] ?? match[4] ?? match[6] ?? "";
    if (!name || /^(?:if|for|while|switch|catch|return|new|typeof|await)$/.test(name)) continue;
    const open = file.code.indexOf("{", match.index + match[0].length - 1);
    if (open === -1) continue;
    const close = matchBrace(file.code, open);
    if (close === -1) continue;
    found.push({
      name,
      parameters,
      startLine: file.lineAt(match.index),
      endLine: file.lineAt(close)
    });
    declaration.lastIndex = open + 1;
  }
  return found;
}

function matchBrace(code, open) {
  let depth = 0;
  for (let index = open; index < code.length; index += 1) {
    if (code[index] === "{") depth += 1;
    else if (code[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function findPythonFunctions(file) {
  const found = [];
  for (let index = 0; index < file.lines.length; index += 1) {
    const match = file.lines[index].match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!match) continue;
    const baseIndent = indentWidth(match[1]);
    let end = index + 1;
    for (let cursor = index + 1; cursor < file.lines.length; cursor += 1) {
      const text = file.lines[cursor];
      if (!text.trim()) continue;
      if (indentWidth(text) <= baseIndent) break;
      end = cursor;
    }
    found.push({ name: match[2], parameters: match[3], startLine: index + 1, endLine: end + 1 });
  }
  return found;
}

function splitParameters(parameters) {
  let depth = 0;
  const pieces = [];
  let current = "";
  for (const char of parameters) {
    if ("([{<".includes(char)) depth += 1;
    if (")]}>".includes(char)) depth -= 1;
    if (char === "," && depth === 0) {
      pieces.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  pieces.push(current);
  return pieces.map((piece) => piece.trim()).filter((piece) => piece && piece !== "self" && piece !== "cls");
}

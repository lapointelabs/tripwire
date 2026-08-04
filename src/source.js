/**
 * Lightweight lexical pass over a source file.
 *
 * Tripwire deliberately avoids per-language parsers so it can cover C#, Python, and
 * TypeScript with one engine and no runtime dependencies. The trade-off is that raw
 * regexes match inside strings and comments, which is the classic source of false
 * positives in this kind of tool. This module removes that trade-off: it produces a
 * `code` view with every comment and string body blanked out (offsets preserved), plus
 * separate indexes of the comments and string literals for the rules that specifically
 * want to inspect them.
 */

const SYNTAX = {
  javascript: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'", "`"], template: "`", regex: true },
  typescript: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'", "`"], template: "`", regex: true },
  vue: { line: ["//"], block: [["/*", "*/"], ["<!--", "-->"]], quotes: ["\"", "'", "`"], template: "`", regex: true },
  svelte: { line: ["//"], block: [["/*", "*/"], ["<!--", "-->"]], quotes: ["\"", "'", "`"], template: "`", regex: true },
  csharp: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'"], verbatim: true },
  java: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'"] },
  kotlin: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'"] },
  go: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'", "`"] },
  rust: { line: ["//"], block: [["/*", "*/"]], quotes: ["\"", "'"] },
  php: { line: ["//", "#"], block: [["/*", "*/"]], quotes: ["\"", "'"] },
  python: { line: ["#"], block: [], quotes: ["\"", "'"], triple: true },
  ruby: { line: ["#"], block: [], quotes: ["\"", "'"] },
  shell: { line: ["#"], block: [], quotes: ["\"", "'"] },
  yaml: { line: ["#"], block: [], quotes: ["\"", "'"] },
  toml: { line: ["#"], block: [], quotes: ["\"", "'"] },
  sql: { line: ["--"], block: [["/*", "*/"]], quotes: ["'", "\""] },
  json: { line: [], block: [], quotes: ["\""] },
  markdown: { line: [], block: [], quotes: [] },
  dotenv: { line: ["#"], block: [], quotes: ["\"", "'"] }
};

const FALLBACK = { line: ["//", "#"], block: [["/*", "*/"]], quotes: ["\"", "'"] };

function syntaxFor(language) {
  return SYNTAX[language] || FALLBACK;
}

function startsWith(text, index, token) {
  return text.startsWith(token, index);
}

/**
 * Blank out comments and string bodies while preserving every character offset, so a
 * match position in the masked text maps directly back to the original file.
 */
export function lexSource(text, language) {
  const syntax = syntaxFor(language);
  const masked = new Array(text.length);
  const comments = [];
  const strings = [];
  let line = 1;
  let index = 0;

  const lineStarts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") lineStarts.push(i + 1);
  }

  const blank = (from, to, char = " ") => {
    for (let i = from; i < to && i < text.length; i += 1) {
      masked[i] = text[i] === "\n" ? "\n" : char;
    }
  };

  while (index < text.length) {
    const char = text[index];
    if (char === "\n") {
      masked[index] = "\n";
      line += 1;
      index += 1;
      continue;
    }

    const lineToken = syntax.line.find((token) => startsWith(text, index, token));
    if (lineToken) {
      let end = text.indexOf("\n", index);
      if (end === -1) end = text.length;
      comments.push({ line, kind: "line", text: text.slice(index + lineToken.length, end).trim(), start: index, end });
      blank(index, end);
      index = end;
      continue;
    }

    const blockToken = syntax.block.find(([open]) => startsWith(text, index, open));
    if (blockToken) {
      const [open, close] = blockToken;
      let end = text.indexOf(close, index + open.length);
      end = end === -1 ? text.length : end + close.length;
      const body = text.slice(index + open.length, Math.max(index + open.length, end - close.length));
      comments.push({ line, kind: "block", text: body.trim(), start: index, end });
      blank(index, end);
      line += countNewlines(text, index, end);
      index = end;
      continue;
    }

    // Python / Ruby triple-quoted strings double as docstrings, so they are indexed as
    // both a string and a comment: rules about misleading prose need to see them.
    if (syntax.triple && (startsWith(text, index, "\"\"\"") || startsWith(text, index, "'''"))) {
      const delimiter = text.slice(index, index + 3);
      let end = text.indexOf(delimiter, index + 3);
      end = end === -1 ? text.length : end + 3;
      const body = text.slice(index + 3, Math.max(index + 3, end - 3));
      strings.push({ line, quote: delimiter, value: body, start: index, end, interpolated: false });
      comments.push({ line, kind: "doc", text: body.trim(), start: index, end });
      blank(index, end);
      line += countNewlines(text, index, end);
      index = end;
      continue;
    }

    // C# verbatim (@"...") and interpolated ($"...", $@"...") string prefixes.
    if (syntax.verbatim && (char === "@" || char === "$") && /["$@]/.test(text[index + 1] || "")) {
      const prefixMatch = text.slice(index).match(/^[$@]{1,2}"/);
      if (prefixMatch) {
        const prefix = prefixMatch[0];
        const verbatim = prefix.includes("@");
        const quoteStart = index + prefix.length;
        const end = scanString(text, quoteStart, "\"", { verbatim });
        strings.push({
          line,
          quote: prefix,
          value: text.slice(quoteStart, Math.max(quoteStart, end - 1)),
          start: index,
          end,
          interpolated: prefix.includes("$")
        });
        blank(index, end);
        line += countNewlines(text, index, end);
        index = end;
        continue;
      }
    }

    // Regex literals. Comment tokens are matched above, so any `/` reaching here is
    // either division or the start of a pattern. Patterns routinely contain SQL
    // keywords, `eval`, and path fragments — a validation library's own rules would
    // otherwise be reported as the vulnerabilities it exists to prevent.
    if (syntax.regex && char === "/" && regexCanStartHere(masked, index)) {
      const end = scanRegex(text, index);
      if (end > index) {
        strings.push({ line, quote: "/", value: text.slice(index + 1, end - 1), start: index, end, interpolated: false });
        blank(index, end);
        index = end;
        continue;
      }
    }

    if (syntax.quotes.includes(char)) {
      const end = scanString(text, index + 1, char, { verbatim: false });
      const value = text.slice(index + 1, Math.max(index + 1, end - 1));
      strings.push({
        line,
        quote: char,
        value,
        start: index,
        end,
        interpolated: char === syntax.template ? /\$\{/.test(value) : /\{[^}]*\}/.test(value) && language === "python"
      });
      // Template literals keep their `${...}` expressions visible in the masked view:
      // those are real code, and a rule looking for interpolated SQL needs to see them.
      if (char === syntax.template) {
        blankTemplateOutsideExpressions(text, index, end, masked);
      } else {
        blank(index, end);
      }
      line += countNewlines(text, index, end);
      index = end;
      continue;
    }

    masked[index] = char;
    index += 1;
  }

  for (let i = 0; i < text.length; i += 1) {
    if (masked[i] === undefined) masked[i] = text[i] === "\n" ? "\n" : " ";
  }

  return { code: masked.join(""), comments, strings, lineStarts };
}

/**
 * A `/` begins a regex only where an operand is expected. Looking back at the last
 * emitted non-whitespace character distinguishes `a / b` from `split(/x/)` without
 * needing a full expression parser.
 */
function regexCanStartHere(masked, index) {
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const char = masked[cursor];
    if (char === undefined || char === " ") continue;
    if (char === "\n") return true;
    if ("=(,[!&|?{};:+-*%~^<>".includes(char)) return true;
    // `return /x/`, `typeof /x/`, `case /x/` — a keyword ending an operand-expecting slot.
    // `masked` is a character array under construction, so join before matching.
    const word = masked.slice(Math.max(0, cursor - 10), cursor + 1).join("").match(/[A-Za-z]+$/);
    return Boolean(word && /^(?:return|typeof|instanceof|in|of|case|do|else|yield|await|new|delete|void)$/.test(word[0]));
  }
  return true;
}

/** Scan a regex literal to its closing delimiter, honouring escapes and character classes. */
function scanRegex(text, start) {
  let index = start + 1;
  let inClass = false;
  while (index < text.length) {
    const char = text[index];
    if (char === "\n") return start; // unterminated — it was division after all
    if (char === "\\") {
      index += 2;
      continue;
    }
    if (char === "[") inClass = true;
    else if (char === "]") inClass = false;
    else if (char === "/" && !inClass) {
      index += 1;
      while (index < text.length && /[dgimsuvy]/.test(text[index])) index += 1;
      return index;
    }
    index += 1;
  }
  return start;
}

function scanString(text, from, quote, { verbatim }) {
  let index = from;
  while (index < text.length) {
    const char = text[index];
    if (verbatim) {
      if (char === quote) {
        if (text[index + 1] === quote) {
          index += 2;
          continue;
        }
        return index + 1;
      }
      index += 1;
      continue;
    }
    if (char === "\\") {
      index += 2;
      continue;
    }
    if (char === quote) return index + 1;
    index += 1;
  }
  return text.length;
}

function blankTemplateOutsideExpressions(text, start, end, masked) {
  let index = start;
  let depth = 0;
  while (index < end) {
    if (depth === 0 && text.startsWith("${", index)) {
      depth = 1;
      masked[index] = "$";
      masked[index + 1] = "{";
      index += 2;
      continue;
    }
    if (depth > 0) {
      if (text[index] === "{") depth += 1;
      if (text[index] === "}") depth -= 1;
      masked[index] = text[index];
      index += 1;
      continue;
    }
    masked[index] = text[index] === "\n" ? "\n" : " ";
    index += 1;
  }
}

function countNewlines(text, from, to) {
  let count = 0;
  for (let i = from; i < to && i < text.length; i += 1) {
    if (text[i] === "\n") count += 1;
  }
  return count;
}

/** Build the object every rule receives. */
export function prepareFile(file, text) {
  const lexed = lexSource(text, file.language);
  const lines = text.split(/\r?\n/);
  return {
    ...file,
    text,
    lines,
    code: lexed.code,
    comments: lexed.comments,
    strings: lexed.strings,
    lineStarts: lexed.lineStarts,
    lineAt(offset) {
      let low = 0;
      let high = lexed.lineStarts.length - 1;
      while (low < high) {
        const middle = Math.ceil((low + high) / 2);
        if (lexed.lineStarts[middle] <= offset) low = middle;
        else high = middle - 1;
      }
      return low + 1;
    },
    lineText(number) {
      return lines[number - 1] ?? "";
    }
  };
}

/**
 * Iterate regex matches over a chosen view of the file, yielding 1-based line numbers.
 *
 * Some rules must scan the raw `text` view because the thing they look for lives inside
 * a string literal, which the masked view blanks. Those scans still skip comments: prose
 * describing a vulnerability is not the vulnerability, and a rule that cannot tell the
 * difference reports every security discussion in the codebase as a finding.
 */
export function* matches(file, regex, view = "code") {
  const haystack = view === "code" ? file.code : file.text;
  const pattern = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
  let match;
  while ((match = pattern.exec(haystack)) !== null) {
    if (match[0].length === 0) {
      pattern.lastIndex += 1;
      continue;
    }
    if (view !== "code" && isSpecification(file, match.index)) continue;
    yield { match, index: match.index, line: file.lineAt(match.index) };
  }
}

/**
 * Is this offset inside prose or inside a regex literal?
 *
 * Both describe code rather than being it. A comment explaining an injection risk is not
 * an injection, and a pattern written to *detect* `bypassPermissions` is not a call that
 * sets it — which is why linters, validators, and WAF rulesets get reported as the very
 * vulnerabilities they exist to catch. Ordinary string literals are deliberately not
 * covered: rules use the text view precisely to see inside them.
 */
function isSpecification(file, offset) {
  for (const comment of file.comments) {
    if (offset >= comment.start && offset < comment.end) return true;
  }
  for (const literal of file.strings) {
    if (literal.quote === "/" && offset >= literal.start && offset < literal.end) return true;
  }
  return false;
}

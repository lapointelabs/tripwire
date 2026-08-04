import { matches } from "../source.js";

/** Names that almost always carry data an attacker or an external system controls. */
export const UNTRUSTED_NAME = /\b(req|request|ctx\.request|body|params|query|searchParams|formData|userInput|user_input|userMessage|user_message|untrusted|payload|externalInput|clientInput|Request\.(Query|Form|Body|Params)|HttpContext\.Request)\b/;

/** Placeholder values that look like secrets but are not. */
export const PLACEHOLDER = /^(?:|x{3,}|y{3,}|\*+|\.+|-+|changeme|change_me|placeholder|example|test|dummy|todo|none|null|undefined|your[-_ ]?\w*|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[sd]|process\.env\..*|os\.environ.*|secret|password|token|apikey|api[-_]?key)$/i;

export function isPlaceholder(value) {
  const trimmed = String(value).trim();
  if (trimmed.length < 8) return true;
  if (PLACEHOLDER.test(trimmed)) return true;
  if (/^(?:https?:\/\/|\.\/|\/|\w+\/)/.test(trimmed)) return true;
  if (/\$\{|\{\{|%\(|\bos\.getenv\b|\bprocess\.env\b/.test(trimmed)) return true;
  // A value with no entropy variety (all one character class, few distinct chars) is prose.
  const distinct = new Set(trimmed).size;
  return distinct < 6;
}

/**
 * Names in this file that hold request-controlled data.
 *
 * A regex over conventional names (`req`, `body`, `params`) covers Express-shaped code
 * and misses the framework that states it outright. ASP.NET binds an action parameter
 * from the request with an attribute — `[FromQuery] string host` — and after that the
 * value travels under an ordinary domain name like `host` or `id` with nothing about the
 * identifier to suggest an attacker chose it. Reading the binding is the difference
 * between a medium-confidence guess and a fact.
 */
export function untrustedNames(file) {
  const names = new Set();

  // ASP.NET model binding: [FromQuery] string host, [FromBody] Dto payload, …
  for (const match of file.text.matchAll(/\[From(?:Query|Route|Body|Form|Header)(?:\([^)]*\))?\]\s*(?:params\s+)?[\w<>,.\[\]?]+\s+(\w+)/g)) {
    names.add(match[1]);
  }
  // A minimal-API or controller parameter read straight off the request.
  for (const match of file.text.matchAll(/\b(?:Request\.Query|Request\.Form|Request\.Headers|Request\.RouteValues)\s*\[[^\]]+\]\s*;?/g)) {
    const assignment = file.text.slice(Math.max(0, match.index - 80), match.index).match(/(?:var|string|string\?)\s+(\w+)\s*=\s*$/);
    if (assignment) names.add(assignment[1]);
  }
  // Node: const { host } = req.query / req.body / req.params
  for (const match of file.text.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\.(?:query|body|params)/g)) {
    for (const piece of match[1].split(",")) {
      const name = piece.split(":").pop().trim();
      if (/^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
    }
  }
  for (const match of file.text.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:req|request)\.(?:query|body|params)\b/g)) {
    names.add(match[1]);
  }
  names.delete("");
  return names;
}

/** The shell interpreter a nearby `FileName`/executable assignment names, if any. */
export function interpreterFor(file, index) {
  const window = file.text.slice(Math.max(0, index - 400), index + 200);
  const match = window.match(/(?:FileName|executable|command|shell)\s*[:=]\s*["'`]([^"'`]*\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|bash|zsh|sh)\b[^"'`]*)["'`]/i)
    || window.match(/["'`](\/bin\/(?:sh|bash|zsh))["'`]/);
  return match ? match[1] : null;
}

/** The identifier immediately preceding a template literal, if it is a tagged template. */
export function templateTag(file, literal) {
  const before = file.text.slice(Math.max(0, literal.start - 64), literal.start);
  const match = before.match(/([A-Za-z_$][\w$.]*)\s*$/);
  return match ? match[1] : null;
}

/** Text immediately before a string literal, used to identify the call it sits inside. */
export function contextBefore(file, offset, span = 120) {
  return file.text.slice(Math.max(0, offset - span), offset);
}

export function contextAfter(file, offset, span = 200) {
  return file.text.slice(offset, Math.min(file.text.length, offset + span));
}

/** Every string literal in the file that contains an interpolation or concatenation site. */
export function interpolatedStrings(file) {
  return file.strings.filter((literal) => {
    if (literal.interpolated) return true;
    if (literal.quote === "`" && /\$\{/.test(literal.value)) return true;
    if (/^\$/.test(literal.quote)) return true;
    return false;
  });
}

/** Does this string literal look like SQL? */
export function looksLikeSql(value) {
  if (!/\b(select|insert\s+into|update|delete\s+from|merge\s+into|drop\s+table|alter\s+table|create\s+table|union\s+select)\b/i.test(value)) {
    return false;
  }
  return /\b(from|into|set|where|values|table|join)\b/i.test(value);
}

/** Does this string literal read like a model prompt? */
export function looksLikePrompt(value) {
  const normalized = value.toLowerCase();
  const signals = [
    /\byou are\b/, /\byour task\b/, /\bassistant\b/, /\bsystem prompt\b/, /\brespond (?:with|in)\b/,
    /\banswer the\b/, /\bsummari[sz]e\b/, /\bthe user\b/, /\binstructions?:/, /\bdo not\b.*\b(reveal|disclose)\b/,
    /<\/?(?:instructions|context|document|system)>/
  ];
  return signals.filter((pattern) => pattern.test(normalized)).length >= 1 && value.length >= 40;
}

/** Interpolation expressions inside a template literal or f-string. */
export function interpolationExpressions(value) {
  const expressions = new Set();
  for (const match of value.matchAll(/\$\{([^}]*)\}/g)) expressions.add(match[1].trim());
  // Python f-string holes. The `$` in the lookbehind matters: without it this also
  // matches the inner braces of a JavaScript `${...}`, reporting each one twice.
  for (const match of value.matchAll(/(?<![{$])\{([A-Za-z_][\w.\[\]'"()]*)\}(?!\})/g)) {
    expressions.add(match[1].trim());
  }
  expressions.delete("");
  return [...expressions];
}

/**
 * Collect assignment targets that receive the result of a model call, so a later rule
 * can ask whether that value reaches a dangerous sink.
 */
const MODEL_CALL = /\b(?:messages\.create|chat\.completions\.create|completions\.create|generateText|generateObject|streamText|\.invoke|\.predict|\.run|ChatCompletion\.create|GetChatCompletionsAsync|CompleteAsync)\s*\(/;

export function modelResultBindings(file) {
  const bindings = [];
  for (const { match, line, index } of matches(file, MODEL_CALL)) {
    const lineStart = file.lineStarts[line - 1] ?? index;
    const prefix = file.text.slice(lineStart, index);
    // The receiver path sits between `await` and the method — `client.beta.messages.create`
    // — so the assignment pattern has to tolerate it, not require the call to follow `await`
    // directly.
    const assignment = prefix.match(/(?:const|let|var|final)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:await\s+)?[\w$.]*$/);
    if (assignment) bindings.push({ name: assignment[1], line });
  }
  return bindings;
}

export function indentWidth(lineText) {
  const match = lineText.match(/^[\t ]*/);
  if (!match) return 0;
  return match[0].replace(/\t/g, "    ").length;
}

/** Trim a source line for display in a report. */
export function evidenceOf(file, line, maxLength = 160) {
  const text = file.lineText(line).trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

export const JS = ["javascript", "typescript", "vue", "svelte"];
export const PY = ["python"];
export const CS = ["csharp"];

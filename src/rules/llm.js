import { matches } from "../source.js";
import {
  contextAfter, evidenceOf, interpolationExpressions, looksLikePrompt,
  modelResultBindings, UNTRUSTED_NAME
} from "./helpers.js";

/** Sinks where a model's output stops being text and starts being an instruction. */
const DANGEROUS_SINKS = [
  [/\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(/, "a shell command"],
  [/(?<![.\w])eval\s*\(|new\s+Function\s*\(/, "a code evaluator"],
  [/\b(?:query|execute|executeSql|FromSqlRaw|ExecuteSqlRaw)\s*\(/, "a database query"],
  [/\b(?:writeFile|writeFileSync|appendFile|unlink|rm|rmdir|File\.WriteAll\w+|File\.Delete)\s*\(/, "a filesystem write"],
  [/\.innerHTML\s*=|dangerouslySetInnerHTML/, "an HTML sink"],
  [/\bfetch\s*\(|axios\.(?:get|post)\s*\(|HttpClient\b/, "an outbound HTTP request"]
];

/** Phrases that only appear in text trying to redirect a model. */
export const INJECTION_PHRASES = /\b(?:ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions?|prompts?|rules?)|disregard (?:the |all |any )?(?:previous|above|prior|system)|you are now|new instructions?:|system prompt:|forget (?:everything|all previous)|override (?:your |the )?(?:instructions?|rules?|safety)|do not (?:tell|inform|mention to) the user|reveal (?:your|the) (?:system )?prompt|act as (?:if you are |an? )?(?:unrestricted|jailbroken|DAN)|print (?:your |the )?(?:system prompt|instructions))\b/i;

export const llmRules = [
  {
    id: "llm/untrusted-input-in-prompt",
    category: "agent-safety",
    severity: "high",
    title: "External data spliced into a prompt",
    why: "A model cannot tell your instructions apart from text that arrived inside the data. When request bodies, documents, or scraped pages are concatenated into the same string as your directions, whoever wrote that content is writing part of your prompt.",
    fix: "Keep instructions in the system prompt and put external content in a separate user-role message, wrapped in explicit delimiters, with a standing instruction that content inside the delimiters is data to analyze and never a directive to follow.",
    languages: "*",
    requires: "ai",
    confidence: "medium",
    aiTriage: true,
    scan(file) {
      const findings = [];
      for (const literal of file.strings) {
        const expressions = interpolationExpressions(literal.value);
        if (!expressions.length || !looksLikePrompt(literal.value)) continue;
        const risky = expressions.filter((expression) => UNTRUSTED_NAME.test(expression)
          || /\b(?:content|text|message|comment|document|email|description|body|html|page|transcript|file|input|data|prompt)\b/i.test(expression));
        if (!risky.length) continue;
        // Delimited content with a standing "treat as data" instruction is the mitigation.
        const delimited = /<\/?(?:document|user_?(?:input|content|data)|untrusted|external|context)>/i.test(literal.value)
          && /\b(?:never|do not|don't)\b[^.]{0,80}\b(?:follow|obey|treat as instructions?|execute)\b/i.test(literal.value);
        if (delimited) continue;
        findings.push({
          line: literal.line,
          evidence: evidenceOf(file, literal.line),
          message: `Prompt text interpolates \`${risky.slice(0, 3).join("`, `")}\` with no data/instruction boundary.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "llm/model-output-to-sink",
    category: "agent-safety",
    severity: "critical",
    title: "Model output reaches an execution sink",
    why: "Model output is untrusted input that happens to be well formatted. Once it can reach a shell, a query, or the filesystem, a single injected instruction anywhere upstream — in a scraped page, a support ticket, a PDF — turns into code running on your machine.",
    fix: "Do not execute model output directly. Have the model choose from a fixed set of named operations with typed parameters, validate the choice against that set, and run the operation yourself.",
    languages: "*",
    requires: "ai",
    confidence: "medium",
    aiTriage: true,
    scan(file) {
      const bindings = modelResultBindings(file);
      if (!bindings.length) return [];
      const findings = [];
      for (const binding of bindings) {
        const reference = new RegExp(`\\b${escape(binding.name)}\\b`);
        for (const [sink, label] of DANGEROUS_SINKS) {
          for (const { line, index } of matches(file, sink)) {
            if (line <= binding.line) continue;
            if (line - binding.line > 60) continue;
            const call = contextAfter(file, index, 260);
            if (!reference.test(call)) continue;
            if (findings.some((existing) => existing.line === line)) continue;
            findings.push({
              line,
              evidence: evidenceOf(file, line),
              message: `\`${binding.name}\` holds model output (line ${binding.line}) and reaches ${label} here.`,
              confidence: "high"
            });
          }
        }
      }
      return findings;
    }
  },

  {
    id: "llm/dynamic-tool-description",
    category: "agent-safety",
    severity: "critical",
    title: "Tool description built from a variable",
    why: "An agent reads tool descriptions as instructions and weighs them as heavily as the system prompt. A description assembled from data means whoever controls that data can tell the agent what to do, and no amount of prompt hardening elsewhere helps.",
    fix: "Make every tool name, description, and parameter description a static string literal. If a tool must describe dynamic state, put that state in the tool's return value where it is read as data.",
    languages: "*",
    requires: "ai",
    confidence: "high",
    scan(file) {
      const findings = [];
      const pattern = /\b(?:description|instructions?|prompt|systemPrompt|system_prompt)\s*[:=]\s*(?:`[^`]*\$\{|f["'][^"']*\{|\$"|[A-Za-z_$][\w$.]*\s*(?:\+|\.concat|\.format|`))/;
      for (const { line, index } of matches(file, pattern, "text")) {
        const window = file.text.slice(Math.max(0, index - 500), index + 200);
        // Only interesting where the surrounding object is actually a tool definition.
        if (!/\b(?:tool|Tool|function_declarations|inputSchema|input_schema|parameters|registerTool|addTool|@tool|FunctionDefinition|setRequestHandler)\b/.test(window)) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "A tool description is assembled at runtime rather than declared as a literal.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "llm/permission-bypass",
    category: "agent-safety",
    severity: "high",
    title: "Agent permission checks disabled",
    why: "These switches remove the confirmation step between a model deciding to act and the action happening. They are reasonable in a throwaway sandbox and a standing incident in anything with credentials or a network.",
    fix: "Remove the bypass from committed code. Where unattended runs are genuinely needed, scope them with an explicit allow-list of tools and run them in a container that holds nothing you would mind losing.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const patterns = [
        [/dangerouslySkipPermissions\s*[:=]\s*true|--dangerously-skip-permissions/, "Permission prompts are skipped entirely."],
        [/permissionMode\s*[:=]\s*["']bypassPermissions["']/, "`bypassPermissions` disables every tool confirmation."],
        [/\bautoApprove\s*[:=]\s*(?:true|\[["'][*]["']\])/, "Tool calls are auto-approved."],
        [/\byolo\s*[:=]\s*true|--yolo\b/, "Confirmation is disabled."],
        [/\bapproval[_-]?mode\s*[:=]\s*["'](?:never|none|full[-_]?auto)["']/, "Approvals are set to never prompt."],
        [/\bsandbox\s*[:=]\s*["']?(?:false|none|danger[-_]full[-_]access)/, "The tool sandbox is disabled."]
      ];
      for (const [pattern, message] of patterns) {
        for (const { line } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;
          findings.push({ line, evidence: evidenceOf(file, line), message, confidence: "high" });
        }
      }
      return findings;
    }
  },

  {
    id: "llm/secret-in-prompt",
    category: "agent-safety",
    severity: "high",
    title: "Secret interpolated into prompt text",
    why: "Anything placed in a prompt leaves your process, is retained by the provider, and can be coaxed back out by a later turn of the same conversation. A credential in a prompt is a credential you have disclosed to a third party and to every subsequent message in that thread.",
    fix: "Keep credentials in the code that makes the call, never in the text sent to the model. If the model needs to trigger an authenticated action, expose it as a tool that holds the credential server-side.",
    languages: "*",
    requires: "ai",
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const literal of file.strings) {
        const expressions = interpolationExpressions(literal.value);
        if (!expressions.length) continue;
        if (!looksLikePrompt(literal.value) && !/\bprompt|message|system\b/i.test(literal.value.slice(0, 80))) continue;
        const secrets = expressions.filter((expression) => /\b(?:apiKey|api_key|secret|password|token|credential|privateKey|private_key|process\.env|os\.environ)\b/i.test(expression));
        if (!secrets.length) continue;
        findings.push({
          line: literal.line,
          evidence: evidenceOf(file, literal.line),
          message: `Prompt text interpolates \`${secrets[0]}\`.`,
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "llm/unbounded-model-input",
    category: "agent-safety",
    severity: "medium",
    title: "External content sent to a model without a size bound",
    why: "Fetched pages, uploaded files, and database rows have no natural upper bound. Without a limit this is both a cost incident waiting to happen and a way for a caller to push your real instructions out of the model's effective attention.",
    fix: "Truncate external content to a documented budget before it reaches the request, and count tokens rather than characters if the limit matters.",
    languages: "*",
    requires: "ai",
    confidence: "low",
    aiTriage: true,
    scan(file) {
      const findings = [];
      const fetchPattern = /\b(?:await\s+)?(?:fetch|axios\.get|requests\.get|HttpClient\b[^;\n]*GetStringAsync|readFile|readFileSync)\s*\(/;
      const fetched = [...matches(file, fetchPattern)].map((entry) => entry.line);
      if (!fetched.length) return [];
      for (const { line } of matches(file, /\b(?:messages\.create|chat\.completions\.create|generateText|generateObject|streamText)\s*\(/)) {
        const nearest = fetched.filter((candidate) => candidate < line && line - candidate <= 40);
        if (!nearest.length) continue;
        const window = file.text.slice(file.lineStarts[Math.max(0, nearest[0] - 1)] ?? 0, file.lineStarts[line] ?? file.text.length);
        if (/\bslice\s*\(|\bsubstring\s*\(|\[:\s*\d|\bTruncate\b|maxLength|max_length|\bLimit\b/i.test(window)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `Content fetched at line ${nearest[0]} is sent to the model with no truncation between.`,
          confidence: "low"
        });
      }
      return findings;
    }
  },

  {
    id: "llm/injection-payload-in-source",
    category: "agent-safety",
    severity: "high",
    title: "Prompt-injection phrasing inside repository content",
    why: "Coding agents read this repository. Text that instructs a model to ignore its directions works the same way whether it arrived over the network or was committed to a fixture, a docstring, or a README — and committed text gets read on every single run.",
    fix: "If this is a test fixture, move it under a clearly named directory and keep it out of any path an agent is pointed at. If it is not a fixture, treat it as tampering and check when it was introduced and by whom.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const { match, line } of matches(file, INJECTION_PHRASES, "text")) {
        if (findings.some((existing) => existing.line === line)) continue;
        const isFixture = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|evals?|benchmarks?)\//.test(file.relative);
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `Text reads as an instruction override: "${match[0].slice(0, 60)}".`,
          confidence: isFixture ? "low" : "high"
        });
      }
      return findings;
    }
  }
];

function escape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

import { readdir } from "node:fs/promises";
import path from "node:path";
import { matches } from "../source.js";
import { readJson, readText } from "../util.js";
import { CS, JS, PY, evidenceOf } from "./helpers.js";

/**
 * Telemetry and third-party data egress.
 *
 * Observability SDKs are configured once, early, by whoever set up the project, and then
 * never read again. That makes them a durable blind spot: a single boolean decides
 * whether every error report carries user identity, cookies, IP addresses, and full
 * request URLs to a vendor outside your trust boundary. Nothing about the running
 * application looks different, no test fails, and the data flows continuously.
 *
 * These rules read as configuration nits until you ask what is actually in the payload.
 */

/** The text between a call's parentheses, balanced so nested calls and objects survive. */
function callArguments(text, callStart) {
  const open = text.indexOf("(", callStart);
  if (open === -1) return null;
  let depth = 0;
  for (let index = open; index < text.length && index < open + 2000; index += 1) {
    if (text[index] === "(") depth += 1;
    else if (text[index] === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, index);
    }
  }
  return null;
}

/** Fields whose presence turns a telemetry identify() call into a PII transfer. */
const PII_FIELDS = /\b(email|e_?mail|username|user_?name|full_?name|first_?name|last_?name|phone|mobile|address|ssn|social_?security|dob|date_?of_?birth|birth_?date|license|passport|tax_?id)\b/i;

export const telemetryRules = [
  {
    id: "telemetry/default-pii-enabled",
    category: "privacy",
    severity: "critical",
    title: "Telemetry SDK configured to send personal data by default",
    why: "This one setting attaches user identity, IP addresses, cookies, and full request URLs — including query strings — to every event the SDK sends. The data leaves your trust boundary continuously, to a vendor with its own access model and retention, and anyone who can read the telemetry project can read it. In an application handling regulated personal data, that is an ongoing unauthorized disclosure rather than a configuration preference.",
    fix: "Turn it off, then attach only the specific non-identifying fields you actually need for debugging — a user id rather than an email, a route template rather than a populated URL. If identity is genuinely required to triage, scrub it at the SDK's send hook so the decision lives in one reviewable place.",
    languages: [...CS, ...JS, ...PY],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const patterns = [
        [/\bSendDefaultPii\s*=\s*true\b/, "`SendDefaultPii = true` sends identity, cookies, and request URLs on every event."],
        [/\bsendDefaultPii\s*:\s*true\b/, "`sendDefaultPii: true` sends identity, cookies, and request URLs on every event."],
        [/\bsend_default_pii\s*=\s*True\b/, "`send_default_pii=True` sends identity, cookies, and request URLs on every event."]
      ];
      for (const [pattern, message] of patterns) {
        for (const { line, index } of matches(file, pattern)) {
          // A scrubbing hook in the same file means someone has at least considered the
          // payload; without one, nothing stands between this flag and the vendor.
          const scrubbed = /\b(?:beforeSend|BeforeSend|SetBeforeSend|before_send|beforeSendTransaction)\b/.test(file.code);
          findings.push({
            line,
            evidence: evidenceOf(file, line),
            message: scrubbed ? `${message} A send hook exists — confirm it removes what this adds.` : message,
            confidence: "high",
            severity: scrubbed ? "high" : "critical",
            index
          });
        }
      }
      return findings;
    }
  },

  {
    id: "telemetry/user-identity-attached",
    category: "privacy",
    severity: "high",
    title: "User identity sent to a telemetry vendor",
    why: "Attaching an email, username, or name to telemetry turns crash reports into an identity feed. It is retained on the vendor's schedule, visible to everyone with project access, and usually outside the scope of the deletion and access-request paths your own database honours.",
    fix: "Send an opaque internal id instead, and resolve it to a person through your own system when you actually need to. That keeps triage possible while leaving the personal data on your side of the boundary.",
    languages: [...JS, ...CS, ...PY],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const calls = /\b(?:Sentry\.setUser|setUser|SentrySdk\.ConfigureScope|datadogRum\.setUser|LogRocket\.identify|posthog\.identify|mixpanel\.identify|analytics\.identify|FS\.identify|FullStory\.identify|bugsnag\.setUser|amplitude\.setUserId)\s*\(/;
      for (const { line, index } of matches(file, calls)) {
        // Read exactly the call's own arguments. A fixed-width window overshoots into
        // whatever follows — a React dependency array listing `user.email`, for instance —
        // and reports the logout `setUser(null)` that is the correct thing to do.
        const args = callArguments(file.text, index);
        if (!args) continue;
        if (/^\s*(?:null|undefined)\s*$/.test(args)) continue;
        const match = args.match(PII_FIELDS);
        if (!match) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `Identity call includes \`${match[0]}\`, which leaves your trust boundary with every event.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "auth/credential-in-query-string",
    category: "security",
    severity: "high",
    title: "Credential accepted from the query string",
    why: "A token in a URL is copied everywhere a URL goes: access logs, proxy and CDN logs, browser history, `Referer` headers on any outbound link, and — most easily missed — telemetry payloads, which record full request URLs by default. Each of those is a place the credential is retained without anyone deciding it should be.",
    fix: "Take the credential from the `Authorization` header, or a cookie scoped to the endpoint. Where a protocol forces the query string, keep the token single-use with a lifetime in seconds and confirm every sink that records URLs — logs *and* telemetry — strips it.",
    languages: [...CS, ...JS, ...PY],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const patterns = [
        /\bRequest\.Query\s*\[\s*"(access_?token|token|api_?key|apikey|auth|password|secret|sig|signature)"\s*\]/i,
        /\bquery\s*\.\s*(access_?token|api_?key|apikey)\b/i,
        /\b(?:searchParams|query|queryParams)\s*(?:\.get\s*\(\s*|\[\s*)["'](access_?token|token|api_?key|apikey|password|secret)["']/i,
        /\brequest\.args\s*(?:\.get\s*\(\s*)?\[?\s*["'](access_?token|token|api_?key|apikey|password)["']/i
      ];
      for (const pattern of patterns) {
        // The parameter name lives inside a string literal, which the masked code view
        // blanks — this rule has to read the raw text. `matches` still skips comments.
        for (const { match, line } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;
          findings.push({
            line,
            evidence: evidenceOf(file, line),
            message: `\`${match[1]}\` is read from the query string, so it is recorded anywhere the URL is.`,
            confidence: "high"
          });
        }
      }
      return findings;
    }
  },

  {
    id: "telemetry/full-trace-sampling",
    category: "privacy",
    severity: "medium",
    title: "Every transaction sampled to telemetry",
    why: "Sampling at 100% means no request is ever the one that stayed inside. Combined with a setting that attaches request data, it is the difference between leaking a sample of user activity and leaking all of it — and it is the shape that turns a small misconfiguration into a large one.",
    fix: "Sample at a rate that reflects what you actually diagnose, and keep full sampling for local development. If a specific route genuinely needs complete traces, raise it for that route rather than globally.",
    languages: [...CS, ...JS, ...PY],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const pattern = /\b(TracesSampleRate|tracesSampleRate|traces_sample_rate|ProfilesSampleRate|profilesSampleRate|replaysSessionSampleRate)\s*[:=]\s*1(?:\.0+)?\b/;
      for (const { match, line, index } of matches(file, pattern)) {
        // An environment-gated value is a deliberate choice, not an oversight — but the
        // gate has to be a branch. Merely mentioning the environment nearby is not one:
        // a neighbouring `o.Debug = env.IsDevelopment()` would otherwise hide this.
        const before = file.text.slice(Math.max(0, index - 250), index);
        if (/\bif\s*\([^)]{0,120}(?:IsDevelopment|isDevelopment|NODE_ENV|ASPNETCORE_ENVIRONMENT|isDev|development)/i.test(before)) continue;
        if (/\?\s*1(?:\.0+)?\s*:/.test(file.lineText(line))) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `\`${match[1]}\` is 1.0, so every transaction is sent.`,
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "telemetry/scrubbed-from-logs-only",
    category: "privacy",
    severity: "high",
    title: "Sensitive URLs kept out of logs but not out of telemetry",
    why: "Code that deliberately suppresses a credential-bearing URL from its log sink shows someone understood the risk. Telemetry SDKs record full request URLs independently of the logging pipeline, so the same value still leaves the system — through the sink nobody adjusted. The comment explaining the log protection makes the gap harder to notice, not easier.",
    fix: "Apply the same suppression at the telemetry SDK's send hook, so both sinks are covered by one reviewable decision. Better still, move the credential out of the URL and neither sink has to be careful.",
    languages: [...CS, ...JS, ...PY],
    requires: null,
    confidence: "medium",
    scan(file) {
      // Only meaningful where both a telemetry SDK and deliberate log suppression exist.
      const hasTelemetry = /\b(?:UseSentry|Sentry\.init|SentrySdk|sentry_sdk|datadogRum|applicationinsights)\b/.test(file.code);
      if (!hasTelemetry) return [];
      const suppression = /\b(?:LogEventLevel\.Verbose|GetLevel|Serilog|redact|scrub|sanitize)\w*\b/;
      if (!suppression.test(file.code)) return [];

      const findings = [];
      const scrubsTelemetry = /\b(?:beforeSend|BeforeSend|SetBeforeSend|before_send)\b/.test(file.code);
      if (scrubsTelemetry) return [];

      for (const { line } of matches(file, /\b(?:GetLevel|LogEventLevel\.Verbose)\b/)) {
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Log output is filtered here, but the telemetry SDK in this file has no send hook doing the same.",
          confidence: "low"
        });
        break; // One finding per file: this is a design observation, not a per-line defect.
      }
      return findings;
    }
  }
];

export const telemetryProjectRules = [
  {
    id: "config/hardcoded-overrides-config",
    category: "correctness",
    severity: "medium",
    title: "Code hardcodes a value that configuration also sets",
    why: "When a setting exists in a config file and is also assigned a literal in code, the config file becomes decorative. Anyone tuning the documented value — in review, in an incident, per environment — changes nothing, and the discrepancy is invisible from either file alone.",
    fix: "Read the value from configuration and delete the literal, so there is one place the setting lives. If the code value is deliberately non-negotiable, remove it from the config file so nobody is misled into tuning it.",
    requires: null,
    confidence: "medium",
    async scanProject(context) {
      const settings = await loadAppSettings(context.root, context.project.directory);
      if (!settings.size) return [];

      const findings = [];
      for (const file of context.preparedFiles) {
        if (file.language !== "csharp") continue;
        for (const { match, line } of matches(file, /\b(\w+)\s*=\s*(true|false|\d+(?:\.\d+)?)\s*[;,]/)) {
          const [, property, literal] = match;
          const configured = settings.get(property);
          if (configured === undefined) continue;
          if (String(configured) === literal) continue;
          findings.push({
            file: file.relative,
            line,
            evidence: evidenceOf(file, line),
            message: `\`${property}\` is ${literal} here but ${JSON.stringify(configured)} in ${settings.get(`${property}::source`)}; the configured value never takes effect.`,
            confidence: "medium"
          });
        }
      }
      return findings.slice(0, 20);
    }
  }
];

/**
 * Flatten every appsettings file to leaf-name → value. Matching on the leaf rather than
 * the full path is deliberate: the code says `o.TracesSampleRate`, the file says
 * `Sentry:TracesSampleRate`, and nothing in the source records that binding.
 */
async function loadAppSettings(root, directory) {
  const settings = new Map();
  let entries = [];
  try {
    entries = await readdir(directory);
  } catch {
    return settings;
  }

  for (const name of entries) {
    if (!/^appsettings.*\.json$/i.test(name)) continue;
    const parsed = await readJson(path.join(directory, name));
    if (!parsed) continue;
    walk(parsed, name);
  }

  function walk(node, source) {
    if (!node || typeof node !== "object") return;
    for (const [key, value] of Object.entries(node)) {
      if (value && typeof value === "object") {
        walk(value, source);
        continue;
      }
      if (typeof value === "boolean" || typeof value === "number") {
        // Keep the first definition: appsettings.json is the base, and environment
        // overlays are expected to differ from it.
        if (!settings.has(key)) {
          settings.set(key, value);
          settings.set(`${key}::source`, source);
        }
      }
    }
  }

  return settings;
}

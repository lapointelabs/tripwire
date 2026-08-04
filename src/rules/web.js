import { matches } from "../source.js";
import { CS, JS, PY, contextAfter, evidenceOf, UNTRUSTED_NAME } from "./helpers.js";

export const webRules = [
  {
    id: "web/raw-html-sink",
    category: "security",
    severity: "high",
    title: "Value rendered as raw HTML",
    why: "These sinks hand a string to the HTML parser instead of the text node. A value that ever contains markup becomes markup, and script inside it runs with the privileges of whoever is viewing the page.",
    fix: "Render the value as text. Where markup genuinely has to pass through, sanitize it with a maintained allow-list sanitizer immediately before the sink, not at the point the data was stored.",
    languages: [...JS, ...CS, ...PY],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const sinks = [
        [/dangerouslySetInnerHTML\s*=\s*\{\{/, "`dangerouslySetInnerHTML` writes the value into the DOM as markup."],
        [/\.innerHTML\s*=\s*(?!["'`]\s*["'`])/, "Assigning to `innerHTML` parses the value as markup."],
        [/\.outerHTML\s*=/, "Assigning to `outerHTML` parses the value as markup."],
        [/\bv-html\s*=/, "`v-html` renders the bound value as markup."],
        [/\{@html\s/, "`{@html}` renders the expression as markup."],
        [/@Html\.Raw\s*\(/, "`Html.Raw` emits the value without encoding."],
        [/\bdocument\.write\s*\(/, "`document.write` parses its argument as markup."],
        [/\|\s*safe\b/, "The `safe` filter disables template autoescaping for this value."],
        [/\bmark_safe\s*\(/, "`mark_safe` disables Django's autoescaping for this value."],
        [/\binsertAdjacentHTML\s*\(/, "`insertAdjacentHTML` parses its argument as markup."]
      ];
      for (const [pattern, message] of sinks) {
        for (const { line } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;
          const evidence = evidenceOf(file, line);
          // A literal empty-string or constant assignment is not a sink worth reporting.
          if (/=\s*["'`][^"'`$]*["'`]\s*;?\s*$/.test(evidence)) continue;
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
    id: "web/permissive-cors",
    category: "security",
    severity: "high",
    title: "Wildcard origin combined with credentials",
    why: "Allowing every origin while also allowing credentials means any site a signed-in user visits can call your API as them and read the response. Browsers reject this pairing on the wire, so the usual result is a config that is both broken and unsafe.",
    fix: "Reflect only origins from an explicit allow-list, and keep `credentials` off for endpoints that do not need a session.",
    languages: [...JS, ...CS, ...PY],
    requires: "web",
    confidence: "high",
    scan(file) {
      const findings = [];
      for (const { line, index } of matches(file, /\bcors\s*\(|\bAllowAnyOrigin\s*\(|Access-Control-Allow-Origin/, "text")) {
        const window = file.text.slice(Math.max(0, index - 200), index + 400);
        const wildcard = /origin\s*:\s*["'`]\*["'`]|AllowAnyOrigin|Access-Control-Allow-Origin["'`\s:]+\*/.test(window);
        const credentials = /credentials\s*:\s*true|AllowCredentials|Access-Control-Allow-Credentials["'`\s:]+true/i.test(window);
        if (!wildcard || !credentials) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Any origin is allowed and credentials are permitted on the same handler.",
          confidence: "high"
        });
      }
      return findings;
    }
  },

  {
    id: "web/disabled-tls-verification",
    category: "security",
    severity: "critical",
    title: "TLS certificate verification disabled",
    why: "Turning off verification keeps the encryption but removes the identity check, which is the part that makes the encryption meaningful. Anyone positioned on the network can present their own certificate and read the traffic.",
    fix: "Remove the override. If a self-signed certificate is genuinely in play, pin that specific certificate authority for that one client rather than disabling the check globally.",
    languages: [...JS, ...PY, ...CS, "go", "ruby"],
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      const patterns = [
        [/rejectUnauthorized\s*:\s*false/, "`rejectUnauthorized: false` accepts any certificate."],
        [/NODE_TLS_REJECT_UNAUTHORIZED["'\]\s]*=\s*["']?0/, "`NODE_TLS_REJECT_UNAUTHORIZED=0` disables verification process-wide."],
        [/verify\s*=\s*False/, "`verify=False` accepts any certificate."],
        [/ServerCertificateValidationCallback\s*(?:\+)?=\s*(?:\([^)]*\)\s*=>\s*true|delegate)/, "The certificate validation callback always returns true."],
        [/ServerCertificateCustomValidationCallback\s*=\s*[^;\n]*(?:true|AlwaysValid)/, "The certificate validation callback always returns true."],
        [/InsecureSkipVerify\s*:\s*true/, "`InsecureSkipVerify: true` accepts any certificate."],
        [/VERIFY_NONE/, "Peer verification is set to none."]
      ];
      for (const [pattern, message] of patterns) {
        for (const { line } of matches(file, pattern)) {
          if (findings.some((existing) => existing.line === line)) continue;
          findings.push({ line, evidence: evidenceOf(file, line), message, confidence: "high" });
        }
      }
      return findings;
    }
  },

  {
    id: "web/weak-hash-for-credentials",
    category: "security",
    severity: "high",
    title: "Fast hash used on a credential",
    why: "MD5, SHA-1 and bare SHA-256 are built to be fast, which is exactly wrong for passwords: commodity hardware tries billions of candidates per second against a stolen table.",
    fix: "Use a memory-hard password hash with a per-user salt — argon2id, scrypt, or bcrypt — and keep the work factor tuned as hardware improves.",
    languages: [...JS, ...PY, ...CS, "go", "java", "php", "ruby"],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const hashCall = /\b(?:createHash\s*\(\s*["'](md5|sha1|sha256)["']|hashlib\.(md5|sha1|sha256)\s*\(|MD5\.Create|SHA1\.Create|SHA256\.Create|md5\s*\()/;
      for (const { line, index } of matches(file, hashCall, "text")) {
        const window = file.text.slice(Math.max(0, index - 300), index + 300);
        if (!/\b(?:password|passwd|pwd|secret|credential|token|apiKey|api_key)\b/i.test(window)) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "A fast hash is applied to a value named like a credential.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "web/insecure-randomness",
    category: "security",
    severity: "medium",
    title: "Non-cryptographic randomness used for a secret",
    why: "`Math.random` and `new Random()` are predictable by design. Given a couple of outputs, the rest of the sequence is recoverable, which makes any token built from them guessable.",
    fix: "Use `crypto.randomUUID()`, `crypto.randomBytes`, `secrets.token_urlsafe`, or `RandomNumberGenerator.GetBytes` for anything that acts as a credential.",
    languages: [...JS, ...PY, ...CS],
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const pattern = /\b(?:Math\.random\s*\(\)|new\s+Random\s*\(|random\.(?:random|randint|choice)\s*\()/;
      for (const { line, index } of matches(file, pattern)) {
        const window = file.text.slice(Math.max(0, index - 250), index + 250);
        if (!/\b(?:token|secret|password|nonce|salt|session|apiKey|api_key|otp|reset|verification|csrf)\b/i.test(window)) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Predictable randomness is used to build a security-sensitive value.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "web/unvalidated-redirect",
    category: "security",
    severity: "medium",
    title: "Redirect target taken from the request",
    why: "A redirect that echoes a request parameter lets an attacker send a link on your domain that lands on theirs. The domain in the address bar is yours right up until the hop, which is what makes the phishing work.",
    fix: "Accept a relative path or a key into a table of known destinations, and reject anything containing a scheme or leading `//`.",
    languages: [...JS, ...CS, ...PY],
    requires: "web",
    confidence: "medium",
    scan(file) {
      const findings = [];
      const pattern = /\b(?:res\.redirect|response\.redirect|Redirect|RedirectPermanent|redirect)\s*\(/;
      for (const { line, index } of matches(file, pattern)) {
        const call = contextAfter(file, index, 160);
        if (!UNTRUSTED_NAME.test(call)) continue;
        if (/\bIsLocalUrl\b|startsWith\s*\(\s*["']\//.test(file.text.slice(Math.max(0, index - 300), index + 160))) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Redirect destination comes from request data with no same-origin check.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "web/missing-authorization-check",
    category: "security",
    severity: "medium",
    title: "Mutating endpoint with no visible authorization",
    why: "An endpoint that writes or deletes without an identity check is reachable by anyone who can guess the route. This is the most common serious finding in real applications and the least visible in review, because nothing about the handler looks wrong.",
    fix: "Apply the project's authorization middleware or attribute to the route, and assert that the authenticated principal actually owns the record being changed.",
    languages: [...JS, ...CS],
    requires: "web",
    confidence: "low",
    scan(file) {
      const findings = [];
      const route = /\b(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)/;
      for (const { match, line, index } of matches(file, route)) {
        const handler = file.text.slice(index, Math.min(file.text.length, index + 700));
        if (/\b(?:auth|authenticate|authorize|requireUser|isAuthenticated|ensureLoggedIn|session\.user|currentUser|verifyToken|guard|can\(|permission)/i.test(handler)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: `\`${match[1]}\` mutates state with no authorization check in the handler.`,
          confidence: "low"
        });
      }
      for (const { line, index } of matches(file, /\[Http(?:Post|Put|Patch|Delete)\]/)) {
        const window = file.text.slice(Math.max(0, index - 400), index + 500);
        if (/\[Authorize|\[ValidateAntiForgeryToken|User\.Identity/.test(window)) continue;
        if (/\[AllowAnonymous\]/.test(window)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "Mutating action has no `[Authorize]` attribute in scope.",
          confidence: "low"
        });
      }
      return findings;
    }
  }
];

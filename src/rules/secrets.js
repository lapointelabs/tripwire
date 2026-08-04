import { matches } from "../source.js";
import { evidenceOf, isPlaceholder } from "./helpers.js";

/**
 * Vendor-issued credentials with a recognizable prefix. These are reported at high
 * confidence because the shape is unambiguous — nobody types `sk-ant-api03-…` by accident.
 */
const TOKEN_SHAPES = [
  [/\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/, "Anthropic API key"],
  [/\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/, "OpenAI API key"],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}/, "GitHub token"],
  [/\bgithub_pat_[A-Za-z0-9_]{40,}/, "GitHub fine-grained token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key id"],
  [/\bASIA[0-9A-Z]{16}\b/, "AWS temporary access key id"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
  [/\bxox[baprs]-[0-9A-Za-z-]{10,}/, "Slack token"],
  [/\bsk_(?:live|test)_[0-9A-Za-z]{24,}/, "Stripe secret key"],
  [/\bglpat-[0-9A-Za-z_-]{20,}/, "GitLab personal access token"],
  [/\bnpm_[0-9A-Za-z]{36}\b/, "npm access token"],
  [/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, "SendGrid API key"],
  [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, "Private key block"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "Signed JSON Web Token"],
  [/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`:]+:[^\s"'`@]{6,}@/, "Connection string with an inline password"]
];

const ASSIGNMENT = /\b([A-Za-z_][\w.]{0,40}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credential|conn(?:ection)?[_-]?string))\s*[:=]\s*(["'`])([^"'`\n]{6,120})\2/i;

export const secretRules = [
  {
    id: "secrets/committed-credential",
    category: "security",
    severity: "critical",
    title: "Credential committed to the repository",
    why: "A secret in version control is readable by everyone with repository access and stays in history after it is deleted from the working tree. Deleting the line is not a fix; the key stays valid until it is rotated.",
    fix: "Rotate the credential first, because it must be assumed compromised. Then move the value to the environment or a secret manager and load it at runtime. Purge the history only after rotation, since rewriting history alone leaves the old key live.",
    languages: "*",
    requires: null,
    confidence: "high",
    scan(file) {
      const findings = [];
      // Fixture and example files legitimately hold key-shaped strings.
      const isFixture = /(?:^|\/)(?:test|tests|__tests__|spec|fixtures?|examples?|mocks?|__mocks__)\//.test(file.relative)
        || /\.(?:test|spec)\.[jt]sx?$/.test(file.relative)
        || /(?:^|\/)\.env\.(?:example|sample|template)$/.test(file.relative);

      for (const [pattern, label] of TOKEN_SHAPES) {
        for (const { match, line } of matches(file, pattern, "text")) {
          if (findings.some((existing) => existing.line === line)) continue;
          findings.push({
            line,
            evidence: redact(evidenceOf(file, line), match[0]),
            message: `${label} appears in source.`,
            confidence: isFixture ? "medium" : "high"
          });
        }
      }

      for (const { match, line } of matches(file, ASSIGNMENT, "text")) {
        if (findings.some((existing) => existing.line === line)) continue;
        const [, name, , value] = match;
        if (isPlaceholder(value)) continue;
        findings.push({
          line,
          evidence: redact(evidenceOf(file, line), value),
          message: `\`${name}\` is assigned a literal value.`,
          confidence: isFixture ? "low" : "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "secrets/logged-credential",
    category: "security",
    severity: "medium",
    title: "Credential written to a log",
    why: "Logs get shipped to aggregators, retained for months, and read by people who were never granted access to the secret itself. A key that reaches stdout has effectively left the trust boundary.",
    fix: "Log a stable identifier for the credential instead of the value — a key id, the last four characters, or nothing at all.",
    languages: "*",
    requires: null,
    confidence: "medium",
    scan(file) {
      const findings = [];
      const logCall = /\b(?:console\.(?:log|info|warn|error|debug)|logger?\.(?:log|info|warn|error|debug)|print|printf|Console\.Write(?:Line)?|fmt\.Print\w*)\s*\(/;
      for (const { line, index } of matches(file, logCall)) {
        const call = file.text.slice(index, Math.min(file.text.length, index + 220));
        if (!/\b(?:password|passwd|secret|apiKey|api_key|accessToken|access_token|privateKey|private_key|clientSecret|credential)\b/i.test(call)) continue;
        // Logging the *absence* of a secret is a normal diagnostic.
        if (/\b(?:missing|not set|undefined|required|redact|\*{3,})\b/i.test(call)) continue;
        if (findings.some((existing) => existing.line === line)) continue;
        findings.push({
          line,
          evidence: evidenceOf(file, line),
          message: "A value named like a credential is passed to a logging call.",
          confidence: "medium"
        });
      }
      return findings;
    }
  },

  {
    id: "secrets/tracked-env-file",
    category: "security",
    severity: "high",
    title: "Environment file holds real values",
    why: "`.env` files are the single most common source of leaked production credentials, because they are easy to create before `.gitignore` is updated and invisible in most editors afterwards.",
    fix: "Confirm the file is ignored by git, rotate anything it contains that reached a commit, and keep only an `.env.example` with empty or obviously fake values in the repository.",
    languages: ["dotenv"],
    requires: null,
    confidence: "high",
    scan(file) {
      if (/\.(?:example|sample|template)$/.test(file.relative)) return [];
      const findings = [];
      for (const { match, line } of matches(file, /^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$/m, "text")) {
        const value = match[2].trim().replace(/^["']|["']$/g, "");
        if (isPlaceholder(value)) continue;
        if (!/(?:KEY|SECRET|TOKEN|PASSWORD|PASS|DSN|URL|URI|CREDENTIAL)/i.test(match[1])) continue;
        findings.push({
          line,
          evidence: redact(`${match[1]}=${value}`, value),
          message: `\`${match[1]}\` has a concrete value in a tracked environment file.`,
          confidence: "high"
        });
      }
      return findings;
    }
  }
];

/** Never reproduce a secret in the report — the report itself gets pasted into chats. */
function redact(text, secret) {
  if (!secret || secret.length < 8) return text;
  const visible = secret.slice(0, 4);
  return text.split(secret).join(`${visible}${"*".repeat(Math.min(12, secret.length - 4))}`);
}

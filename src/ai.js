/**
 * Bring-your-own-model triage layer.
 *
 * The deterministic scan is the product; this layer is optional and additive. It does
 * two things the regex engine cannot: it confirms or refutes low-confidence candidates,
 * and it answers the judgment-shaped questions (does this comment actually contradict
 * the code? is this interpolated value genuinely attacker-influenced?).
 *
 * Every provider goes through its vendor's official SDK rather than hand-rolled HTTP.
 * Model APIs drift — parameters get removed, auth changes, new stop reasons appear — and
 * an SDK absorbs that in a version bump instead of a silent breakage this project has to
 * notice and chase. The SDKs also own retry, backoff, and timeout handling, which is a
 * meaningful amount of subtle code not worth reimplementing per provider.
 *
 * SDKs are imported lazily, so a scan that never triages (the default without a key, and
 * every `--no-ai` run) pays none of the load cost.
 *
 * Requests carry only a finding's evidence line plus a small window of surrounding
 * source — never the whole repository, and never a file the deterministic pass flagged
 * as holding a secret.
 */

const REQUEST_TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;

const PROVIDERS = {
  anthropic: {
    label: "Anthropic",
    envKeys: ["ANTHROPIC_API_KEY"],
    defaultModel: "claude-opus-5",
    package: "@anthropic-ai/sdk",
    async createClient(config) {
      const { default: Anthropic } = await import("@anthropic-ai/sdk");
      return new Anthropic({
        apiKey: config.apiKey,
        ...(config.baseUrl ? { baseURL: config.baseUrl } : {}),
        maxRetries: MAX_RETRIES,
        timeout: REQUEST_TIMEOUT_MS
      });
    },
    async complete(client, request, config) {
      // No temperature/top_p/top_k: those parameters are rejected outright on current
      // Opus and Sonnet models, and this task wants determinism anyway.
      const response = await client.messages.create({
        model: config.model,
        max_tokens: 8000,
        system: request.system,
        messages: [{ role: "user", content: request.user }]
      });
      if (response.stop_reason === "refusal") {
        throw new Error(`model declined the request (${response.stop_details?.category || "unspecified"})`);
      }
      const text = (response.content || [])
        .filter((block) => block.type === "text")
        .map((block) => block.text)
        .join("");
      if (!text) throw new Error("empty response from model");
      return text;
    }
  },

  openai: {
    label: "OpenAI-compatible",
    envKeys: ["OPENAI_API_KEY"],
    defaultModel: "gpt-4o",
    package: "openai",
    async createClient(config) {
      const { default: OpenAI } = await import("openai");
      return new OpenAI({
        apiKey: config.apiKey,
        ...(config.baseUrl ? { baseURL: `${config.baseUrl}/v1` } : {}),
        maxRetries: MAX_RETRIES,
        timeout: REQUEST_TIMEOUT_MS
      });
    },
    async complete(client, request, config) {
      const response = await client.chat.completions.create({
        model: config.model,
        messages: [
          { role: "system", content: request.system },
          { role: "user", content: request.user }
        ],
        response_format: { type: "json_object" }
      });
      const text = response.choices?.[0]?.message?.content;
      if (!text) throw new Error("empty response from model");
      return text;
    }
  },

  /**
   * Cursor exposes agents, not completions — there is no chat endpoint to post a prompt
   * to. `Agent.prompt` is the SDK's one-shot form: send a prompt, get a result, exit.
   *
   * The `local` runtime option is deliberately not set. It would give the agent the
   * working directory, and triage does not need repository access — the excerpts are
   * already in the prompt. Nothing is cloned, no branch is created, no pull request is
   * opened. Agent runs are heavier than a chat call, so batches are larger and run at
   * lower concurrency.
   */
  cursor: {
    label: "Cursor",
    envKeys: ["CURSOR_API_KEY"],
    defaultModel: "composer-2.5",
    package: "@cursor/sdk",
    batchSize: 12,
    concurrency: 2,
    async createClient() {
      const { Agent } = await import("@cursor/sdk");
      return { Agent };
    },
    async complete(client, request, config) {
      const run = await client.Agent.prompt(`${request.system}\n\n---\n\n${request.user}`, {
        apiKey: config.apiKey,
        model: { id: config.model }
      });
      if (run.status && run.status !== "FINISHED") {
        throw new Error(`Cursor run ended as ${run.status}`);
      }
      if (!run.result) throw new Error("Cursor run finished with no result text");
      return run.result;
    }
  },

  ollama: {
    label: "Ollama (local)",
    envKeys: [],
    defaultModel: "qwen2.5-coder",
    package: "ollama",
    async createClient(config) {
      const { Ollama } = await import("ollama");
      return new Ollama({ host: config.baseUrl || process.env.OLLAMA_HOST || "http://127.0.0.1:11434" });
    },
    async complete(client, request, config) {
      const response = await client.chat({
        model: config.model,
        stream: false,
        format: "json",
        messages: [
          { role: "system", content: request.system },
          { role: "user", content: request.user }
        ]
      });
      const text = response.message?.content;
      if (!text) throw new Error("empty response from model");
      return text;
    }
  }
};

export function listProviders() {
  return Object.entries(PROVIDERS).map(([id, provider]) => ({
    id,
    label: provider.label,
    defaultModel: provider.defaultModel,
    package: provider.package,
    envKeys: provider.envKeys
  }));
}

/**
 * Work out which provider to use. An explicit `--provider` always wins; otherwise the
 * first provider with credentials in the environment is chosen, and a local Ollama is
 * never assumed (it would silently pick up a stray daemon).
 */
export function resolveProvider({ provider, model, apiKey, baseUrl }) {
  let chosen = provider;
  if (!chosen) {
    chosen = Object.keys(PROVIDERS).find((id) => PROVIDERS[id].envKeys.some((key) => process.env[key]));
  }
  if (!chosen) {
    const names = [...new Set(Object.values(PROVIDERS).flatMap((entry) => entry.envKeys))];
    return { available: false, reason: `no API key found in the environment (set one of ${names.join(", ")}, or pass --provider ollama)` };
  }
  const definition = PROVIDERS[chosen];
  if (!definition) {
    return { available: false, reason: `unknown provider "${chosen}" — expected one of ${Object.keys(PROVIDERS).join(", ")}` };
  }
  const key = apiKey || definition.envKeys.map((name) => process.env[name]).find(Boolean) || null;
  if (definition.envKeys.length && !key) {
    return { available: false, reason: `${definition.label} selected but ${definition.envKeys[0]} is not set` };
  }
  return {
    available: true,
    id: chosen,
    label: definition.label,
    definition,
    config: {
      model: model || definition.defaultModel,
      apiKey: key,
      baseUrl: baseUrl ? String(baseUrl).replace(/\/+$/, "") : null
    }
  };
}

/**
 * Build the provider's client once per scan.
 *
 * A missing SDK is reported as a plain instruction rather than a module-resolution stack
 * trace: these are declared dependencies, so the realistic cause is an install that
 * skipped them, and the fix is one command.
 */
async function openClient(resolved) {
  try {
    return await resolved.definition.createClient(resolved.config);
  } catch (error) {
    if (error?.code === "ERR_MODULE_NOT_FOUND" || /Cannot find (module|package)/i.test(error?.message || "")) {
      throw new Error(`${resolved.label} needs the "${resolved.definition.package}" package. Install it with: npm install ${resolved.definition.package}`);
    }
    throw error;
  }
}

/** Models wrap JSON in prose or fences often enough that this is worth handling. */
function parseJson(text) {
  const trimmed = text.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start === -1 || end <= start) throw new Error("model did not return JSON");
    return JSON.parse(candidate.slice(start, end + 1));
  }
}

const TRIAGE_SYSTEM = `You are reviewing candidate findings produced by a static analysis tool. The tool matches patterns and cannot read intent, so some candidates are real defects and some are false positives.

For each candidate you are given the rule, the file, the flagged line, and surrounding source. Decide whether the finding is real in this specific code.

Judge only what the evidence shows. If the surrounding code already mitigates the issue — the value is parameterized, validated, escaped, constrained to an allow-list, or provably a constant the caller cannot influence — the finding is not real. If you cannot tell from the code shown, say so with low confidence rather than guessing; an uncertain finding reported honestly is more useful than a confident wrong one.

Respond with JSON only, no prose outside it:
{"verdicts":[{"id":"<candidate id>","real":true|false,"confidence":"high"|"medium"|"low","reason":"<one sentence, max 200 chars>","fix":"<one concrete sentence naming what to change, or null if not real>"}]}

Include exactly one verdict per candidate, using the id given.`;

function buildWindow(finding, fileText) {
  if (!fileText) return finding.evidence;
  const lines = fileText.split(/\r?\n/);
  const start = Math.max(0, finding.line - 9);
  const end = Math.min(lines.length, (finding.endLine || finding.line) + 8);
  return lines
    .slice(start, end)
    .map((text, index) => `${start + index + 1}${start + index + 1 === finding.line ? " >" : "  "} ${text}`)
    .join("\n");
}

/**
 * Send low-confidence findings to the model in small batches and fold the verdicts back
 * in. Findings the deterministic pass is already certain about are never sent — that
 * keeps the cost proportional to the ambiguity, not to the repository size.
 *
 * There is no retry loop here on purpose: the SDKs retry transport failures themselves,
 * and the failures that reach this point (a refusal, a malformed reply) would fail the
 * same way on a second attempt. A failed batch records an error and leaves its findings
 * untouched, so a triage problem can never silently downgrade a real finding.
 */
export async function triageFindings(findings, options) {
  const { resolved, readFile, onProgress = () => {}, budget = 250 } = options;
  // Agent-backed providers pay a fixed startup cost per call, so they want fewer, larger
  // batches; chat endpoints are the opposite. Each provider states its own preference.
  const batchSize = options.batchSize || resolved.definition.batchSize || 6;
  const concurrency = options.concurrency || resolved.definition.concurrency || 3;

  const candidates = findings.filter((finding) => finding.aiTriage && finding.confidence !== "high");
  if (!candidates.length) return { reviewed: 0, changed: 0, skipped: findings.length, errors: [] };

  // Injectable for tests; in normal use this constructs the vendor SDK client.
  const client = options.client || await openClient(resolved);

  const selected = candidates.slice(0, budget);
  const batches = [];
  for (let index = 0; index < selected.length; index += batchSize) {
    batches.push(selected.slice(index, index + batchSize));
  }

  const errors = [];
  let reviewed = 0;
  let changed = 0;
  let cursor = 0;

  const workers = new Array(Math.min(concurrency, batches.length)).fill(null).map(async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= batches.length) return;
      const batch = batches[index];

      const blocks = [];
      for (const finding of batch) {
        const text = await readFile(finding.file);
        blocks.push([
          `--- candidate ${finding.id}`,
          `rule: ${finding.ruleId} — ${finding.title}`,
          `concern: ${finding.message}`,
          `file: ${finding.file}:${finding.line}`,
          "source:",
          buildWindow(finding, text)
        ].join("\n"));
      }

      let parsed;
      try {
        const raw = await resolved.definition.complete(client, {
          system: TRIAGE_SYSTEM,
          user: `Review ${batch.length} candidate${batch.length === 1 ? "" : "s"}.\n\n${blocks.join("\n\n")}`
        }, resolved.config);
        parsed = parseJson(raw);
      } catch (error) {
        errors.push(`batch ${index + 1}: ${error.message}`);
        onProgress({ kind: "batch", index: index + 1, total: batches.length, failed: true });
        continue;
      }

      const byId = new Map(batch.map((finding) => [finding.id, finding]));
      for (const verdict of parsed.verdicts || []) {
        const finding = byId.get(verdict.id);
        if (!finding) continue;
        reviewed += 1;
        const before = finding.confidence;
        finding.verdict = {
          real: verdict.real !== false,
          confidence: verdict.confidence || "medium",
          reason: String(verdict.reason || "").slice(0, 240),
          fix: verdict.fix ? String(verdict.fix).slice(0, 300) : null
        };
        finding.confidence = finding.verdict.real ? finding.verdict.confidence : "refuted";
        if (finding.confidence !== before) changed += 1;
      }
      onProgress({ kind: "batch", index: index + 1, total: batches.length, failed: false });
    }
  });

  await Promise.all(workers);
  return {
    reviewed,
    changed,
    skipped: findings.length - selected.length,
    truncated: candidates.length - selected.length,
    errors
  };
}

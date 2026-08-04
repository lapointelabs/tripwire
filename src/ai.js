/**
 * Bring-your-own-model triage layer.
 *
 * The deterministic scan is the product; this layer is optional and additive. It does
 * two things the regex engine cannot: it confirms or refutes low-confidence candidates,
 * and it answers the judgment-shaped questions (does this comment actually contradict
 * the code? is this interpolated value genuinely attacker-influenced?).
 *
 * Raw HTTP rather than a vendor SDK is deliberate: the whole point is that the user
 * chooses the provider, and Tripwire ships with no runtime dependencies. Requests carry
 * only the finding's evidence line plus a small window of surrounding source — never the
 * whole repository, and never a file the deterministic pass flagged as holding a secret.
 */

const PROVIDERS = {
  anthropic: {
    label: "Anthropic",
    envKeys: ["ANTHROPIC_API_KEY"],
    defaultModel: "claude-opus-5",
    defaultBaseUrl: "https://api.anthropic.com",
    build(request, config) {
      return {
        url: `${config.baseUrl}/v1/messages`,
        headers: {
          "content-type": "application/json",
          "x-api-key": config.apiKey,
          "anthropic-version": "2023-06-01"
        },
        // No temperature/top_p/top_k: those parameters are rejected outright on the
        // current Opus and Sonnet models, and this task wants determinism anyway.
        body: {
          model: config.model,
          max_tokens: 8000,
          system: request.system,
          messages: [{ role: "user", content: request.user }]
        }
      };
    },
    parse(payload) {
      if (payload.stop_reason === "refusal") {
        // A refusal is a decision about this exact payload, not a transient fault —
        // retrying it just spends the same money to be declined again.
        throw permanent(new Error(`model declined the request (${payload.stop_details?.category || "unspecified"})`));
      }
      const text = (payload.content || [])
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
    defaultBaseUrl: "https://api.openai.com",
    build(request, config) {
      return {
        url: `${config.baseUrl}/v1/chat/completions`,
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.apiKey}`
        },
        body: {
          model: config.model,
          messages: [
            { role: "system", content: request.system },
            { role: "user", content: request.user }
          ],
          response_format: { type: "json_object" }
        }
      };
    },
    parse(payload) {
      const text = payload.choices?.[0]?.message?.content;
      if (!text) throw new Error("empty response from model");
      return text;
    }
  },

  ollama: {
    label: "Ollama (local)",
    envKeys: [],
    defaultModel: "qwen2.5-coder",
    defaultBaseUrl: process.env.OLLAMA_HOST || "http://127.0.0.1:11434",
    build(request, config) {
      return {
        url: `${config.baseUrl}/api/chat`,
        headers: { "content-type": "application/json" },
        body: {
          model: config.model,
          stream: false,
          format: "json",
          messages: [
            { role: "system", content: request.system },
            { role: "user", content: request.user }
          ]
        }
      };
    },
    parse(payload) {
      const text = payload.message?.content;
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
    return { available: false, reason: "no API key found in the environment (set ANTHROPIC_API_KEY or OPENAI_API_KEY, or pass --provider ollama)" };
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
      baseUrl: (baseUrl || definition.defaultBaseUrl).replace(/\/+$/, "")
    }
  };
}

async function callModel(resolved, request, { timeoutMs = 120_000, retries = 2 } = {}) {
  const { definition, config } = resolved;
  const { url, headers, body } = definition.build(request, config);

  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal
      });
      if (!response.ok) {
        const detail = (await response.text()).slice(0, 300);
        const retryable = response.status === 429 || response.status >= 500;
        const error = new Error(`${response.status} ${detail}`);
        if (!retryable || attempt === retries) throw error;
        lastError = error;
        await delay(1000 * 2 ** attempt);
        continue;
      }
      return definition.parse(await response.json());
    } catch (error) {
      lastError = error;
      if (error.permanent || error.name === "AbortError" || attempt === retries) break;
      await delay(1000 * 2 ** attempt);
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError || new Error("model request failed");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Mark an error as not worth retrying — the same request would fail the same way. */
function permanent(error) {
  error.permanent = true;
  return error;
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
 */
export async function triageFindings(findings, options) {
  const { resolved, readFile, batchSize = 6, concurrency = 3, onProgress = () => {}, budget = 250 } = options;

  const candidates = findings.filter((finding) => finding.aiTriage && finding.confidence !== "high");
  if (!candidates.length) return { reviewed: 0, changed: 0, skipped: findings.length, errors: [] };

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

      let raw;
      try {
        raw = await callModel(resolved, {
          system: TRIAGE_SYSTEM,
          user: `Review ${batch.length} candidate${batch.length === 1 ? "" : "s"}.\n\n${blocks.join("\n\n")}`
        });
      } catch (error) {
        errors.push(`batch ${index + 1}: ${error.message}`);
        onProgress({ kind: "batch", index: index + 1, total: batches.length, failed: true });
        continue;
      }

      let parsed;
      try {
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

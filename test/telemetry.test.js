import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, describe, test } from "node:test";
import { detectProjects } from "../src/detect.js";
import { scanProject } from "../src/scan.js";
import { prepareFile } from "../src/source.js";
import { telemetryRules } from "../src/rules/telemetry.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureRoot = path.join(root, "test", "fixtures", "telemetry");

const scratch = [];
after(async () => {
  for (const directory of scratch) await rm(directory, { recursive: true, force: true });
});

function ruleFor(id) {
  return telemetryRules.find((rule) => rule.id === id);
}

function run(id, source, language = "typescript") {
  const file = prepareFile({ relative: `x.${language === "csharp" ? "cs" : "ts"}`, language }, source);
  return ruleFor(id).scan(file);
}

async function scanFixture() {
  const projects = await detectProjects(fixtureRoot);
  const project = projects.find((candidate) => candidate.relative === ".");
  return scanProject({ root: fixtureRoot, project });
}

describe("telemetry: default PII", () => {
  test("flags the JavaScript, C#, and Python spellings", () => {
    assert.equal(run("telemetry/default-pii-enabled", "Sentry.init({ sendDefaultPii: true });").length, 1);
    assert.equal(run("telemetry/default-pii-enabled", "o.SendDefaultPii = true;", "csharp").length, 1);
    assert.equal(run("telemetry/default-pii-enabled", "sentry_sdk.init(send_default_pii=True)", "python").length, 1);
  });

  test("does not flag it when disabled", () => {
    assert.deepEqual(run("telemetry/default-pii-enabled", "o.SendDefaultPii = false;", "csharp"), []);
    assert.deepEqual(run("telemetry/default-pii-enabled", "Sentry.init({ sendDefaultPii: false });"), []);
  });

  test("downgrades from critical to high when a send hook exists", () => {
    const bare = run("telemetry/default-pii-enabled", "Sentry.init({ sendDefaultPii: true });");
    assert.equal(bare[0].severity, "critical");

    const hooked = run("telemetry/default-pii-enabled",
      "Sentry.init({ sendDefaultPii: true, beforeSend(event) { delete event.user; return event; } });");
    assert.equal(hooked[0].severity, "high");
    assert.match(hooked[0].message, /confirm it removes/);
  });
});

describe("telemetry: identity", () => {
  test("flags identity calls carrying personal fields", () => {
    const found = run("telemetry/user-identity-attached", "Sentry.setUser({ id: u.id, email: u.email });");
    assert.equal(found.length, 1);
    assert.match(found[0].message, /email/);
  });

  test("does not flag an opaque id, or the logout call that clears identity", () => {
    assert.deepEqual(run("telemetry/user-identity-attached", "Sentry.setUser({ id: user.id });"), []);
    assert.deepEqual(run("telemetry/user-identity-attached", "Sentry.setUser(null);"), []);
  });

  test("reads only the call's own arguments", () => {
    // The React dependency array mentions `user.email`, but the call clears identity.
    // A fixed-width window would overshoot into it and report the wrong line.
    const source = [
      "useEffect(() => {",
      "  return () => { Sentry.setUser(null) }",
      "}, [user.id, user.email, user.username])"
    ].join("\n");
    assert.deepEqual(run("telemetry/user-identity-attached", source), []);
  });
});

describe("telemetry: sampling", () => {
  test("flags full sampling", () => {
    assert.equal(run("telemetry/full-trace-sampling", "o.TracesSampleRate = 1.0;", "csharp").length, 1);
    assert.equal(run("telemetry/full-trace-sampling", "Sentry.init({ tracesSampleRate: 1 });").length, 1);
  });

  test("does not flag a sampled rate", () => {
    assert.deepEqual(run("telemetry/full-trace-sampling", "Sentry.init({ tracesSampleRate: 0.1 });"), []);
  });

  test("does not flag full sampling gated behind a development branch", () => {
    const gated = "if (process.env.NODE_ENV === 'development') { Sentry.init({ tracesSampleRate: 1.0 }); }";
    assert.deepEqual(run("telemetry/full-trace-sampling", gated), []);
  });

  test("still flags it when the environment is merely mentioned nearby", () => {
    // `o.Debug = env.IsDevelopment()` is not a gate. Treating adjacency as one is how this
    // finding hid in the real codebase that motivated the rule.
    const source = [
      "o.Debug = builder.Environment.IsDevelopment();",
      "o.TracesSampleRate = 1.0;"
    ].join("\n");
    assert.equal(run("telemetry/full-trace-sampling", source, "csharp").length, 1);
  });
});

describe("credential in query string", () => {
  test("flags tokens read from the query string across languages", () => {
    const rule = ruleFor("auth/credential-in-query-string");
    const cs = prepareFile({ relative: "P.cs", language: "csharp" },
      'var accessToken = context.Request.Query["access_token"];');
    assert.equal(rule.scan(cs).length, 1);

    const ts = prepareFile({ relative: "r.ts", language: "typescript" },
      'const token = searchParams.get("access_token");');
    assert.equal(rule.scan(ts).length, 1);
  });

  test("does not flag ordinary query parameters", () => {
    const rule = ruleFor("auth/credential-in-query-string");
    const file = prepareFile({ relative: "r.ts", language: "typescript" },
      'const page = searchParams.get("page");');
    assert.deepEqual(rule.scan(file), []);
  });
});

describe("hardcoded config override", () => {
  test("reports a literal that contradicts appsettings", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "tripwire-config-"));
    scratch.push(directory);
    await writeFile(path.join(directory, "appsettings.json"),
      JSON.stringify({ Sentry: { TracesSampleRate: 0.1, SendDefaultPii: false } }), "utf8");
    await mkdir(path.join(directory, "src"), { recursive: true });
    await writeFile(path.join(directory, "App.csproj"),
      '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>', "utf8");
    await writeFile(path.join(directory, "Program.cs"),
      "builder.WebHost.UseSentry(o => {\n  o.TracesSampleRate = 1.0;\n});\n", "utf8");

    const [project] = await detectProjects(directory);
    const result = await scanProject({ root: directory, project, only: ["config/hardcoded-overrides-config"] });
    assert.equal(result.findings.length, 1);
    assert.match(result.findings[0].message, /TracesSampleRate/);
    assert.match(result.findings[0].message, /0\.1/);
    assert.match(result.findings[0].message, /appsettings\.json/);
  });
});

describe("telemetry fixture end to end", () => {
  test("flags every unsafe setting and none of the safe ones", async () => {
    const { findings } = await scanFixture();
    const privacy = findings.filter((finding) => finding.category === "privacy");

    const at = (ruleId, file) => privacy.some((finding) => finding.ruleId === ruleId && finding.file === file);
    assert.ok(at("telemetry/default-pii-enabled", "src/sentry.client.ts"));
    assert.ok(at("telemetry/user-identity-attached", "src/sentry.client.ts"));
    assert.ok(at("telemetry/full-trace-sampling", "src/sentry.client.ts"));

    // safe.ts disables PII, samples at 0.1, and gates full tracing behind NODE_ENV.
    const unsafeInSafeFile = privacy.filter((finding) => finding.file === "src/safe.ts");
    assert.deepEqual(unsafeInSafeFile, [], "the safe configuration must produce no findings");
  });
});

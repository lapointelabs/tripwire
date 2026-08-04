import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { compileIgnorePatterns, exists, isIgnored, readJson, readText, relativePath } from "./util.js";

const SKIP_DIRECTORIES = new Set([
  ".git", ".tripwire", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
  "bin", "obj", "target", "coverage", "__pycache__", ".venv", "venv", ".tox", ".gradle",
  ".idea", ".cache", "Pods", ".terraform", "site-packages", ".svelte-kit", ".turbo"
]);

const MARKER_FILES = new Map([
  ["package.json", "node"],
  ["pyproject.toml", "python"],
  ["requirements.txt", "python"],
  ["setup.py", "python"],
  ["go.mod", "go"],
  ["Cargo.toml", "rust"],
  ["Gemfile", "ruby"],
  ["composer.json", "php"],
  ["pom.xml", "java"],
  ["build.gradle", "java"],
  ["build.gradle.kts", "java"]
]);

const MARKER_EXTENSIONS = new Map([
  [".csproj", "csharp"],
  [".fsproj", "dotnet"],
  [".vbproj", "dotnet"]
]);

const MAX_MARKER_DEPTH = 6;

/**
 * Node dependency fingerprints, checked against the union of dependencies and
 * devDependencies. Order matters: the first match wins as the headline framework
 * because "Next.js" is more useful to a human than "React".
 */
const NODE_FRAMEWORKS = [
  ["next", "Next.js"],
  ["nuxt", "Nuxt"],
  ["@remix-run/react", "Remix"],
  ["@angular/core", "Angular"],
  ["@nestjs/core", "NestJS"],
  ["astro", "Astro"],
  ["svelte", "Svelte"],
  ["vue", "Vue"],
  ["solid-js", "Solid"],
  ["react-native", "React Native"],
  ["electron", "Electron"],
  ["react", "React"],
  ["express", "Express"],
  ["fastify", "Fastify"],
  ["koa", "Koa"],
  ["hono", "Hono"]
];

/**
 * Packages whose presence means the project sends text to a model. This gates the
 * prompt-injection and LLM-output-sink rules: firing them on a project with no model
 * calls is pure noise.
 */
const AI_PACKAGES = [
  "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk", "openai", "ai", "@ai-sdk/anthropic",
  "@ai-sdk/openai", "langchain", "@langchain/core", "llamaindex", "@modelcontextprotocol/sdk",
  "ollama", "cohere-ai", "@google/generative-ai", "groq-sdk", "replicate"
];

const AI_PACKAGES_PYTHON = [
  "anthropic", "openai", "langchain", "llama-index", "litellm", "mcp", "transformers",
  "google-generativeai", "cohere", "ollama", "instructor", "guidance", "dspy"
];

const AI_PACKAGES_DOTNET = [
  "Anthropic", "OpenAI", "Azure.AI.OpenAI", "Microsoft.SemanticKernel", "Microsoft.Extensions.AI"
];

const DB_PACKAGES = [
  "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "mssql", "tedious", "knex",
  "sequelize", "typeorm", "prisma", "@prisma/client", "mongoose", "drizzle-orm", "oracledb"
];

async function collectMarkers(root) {
  const gitignore = await readText(path.join(root, ".gitignore"));
  const ignoreRules = compileIgnorePatterns(gitignore);
  const markers = [];

  async function visit(directory, depth) {
    if (depth > MAX_MARKER_DEPTH) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      const relative = relativePath(root, absolute);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name) || entry.name.startsWith(".")) continue;
        if (isIgnored(ignoreRules, relative, true)) continue;
        await visit(absolute, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const byName = MARKER_FILES.get(entry.name);
      const byExtension = MARKER_EXTENSIONS.get(path.extname(entry.name).toLowerCase());
      const kind = byName || byExtension;
      if (kind) markers.push({ kind, file: absolute, directory, relative });
    }
  }

  await visit(root, 0);
  return markers;
}

function dependencyNames(packageJson) {
  return new Set([
    ...Object.keys(packageJson.dependencies || {}),
    ...Object.keys(packageJson.devDependencies || {}),
    ...Object.keys(packageJson.peerDependencies || {}),
    ...Object.keys(packageJson.optionalDependencies || {})
  ]);
}

function intersects(names, candidates) {
  return candidates.filter((candidate) => names.has(candidate));
}

async function describeNodeProject(root, marker) {
  const packageJson = await readJson(marker.file);
  if (!packageJson) return null;
  const names = dependencyNames(packageJson);
  // A package.json that only declares workspaces is a container, not a project to scan.
  const isWorkspaceRoot = Boolean(packageJson.workspaces) && names.size === 0;
  const framework = NODE_FRAMEWORKS.find(([dependency]) => names.has(dependency));
  const usesTypeScript = names.has("typescript") || await exists(path.join(marker.directory, "tsconfig.json"));
  return {
    kind: "node",
    name: packageJson.name || path.basename(marker.directory),
    directory: marker.directory,
    relative: relativePath(root, marker.directory),
    language: usesTypeScript ? "TypeScript" : "JavaScript",
    framework: framework ? framework[1] : isWorkspaceRoot ? "Workspace root" : "Node.js",
    manifest: marker.relative,
    aiPackages: intersects(names, AI_PACKAGES),
    dbPackages: intersects(names, DB_PACKAGES),
    isWorkspaceRoot
  };
}

async function describePythonProject(root, marker) {
  const raw = (await readText(marker.file)) || "";
  const lowered = raw.toLowerCase();
  const framework = lowered.includes("django") ? "Django"
    : lowered.includes("fastapi") ? "FastAPI"
      : lowered.includes("flask") ? "Flask"
        : lowered.includes("streamlit") ? "Streamlit" : "Python";
  const projectName = raw.match(/^\s*name\s*=\s*["']([^"']+)["']/m)?.[1];
  return {
    kind: "python",
    name: projectName || path.basename(marker.directory),
    directory: marker.directory,
    relative: relativePath(root, marker.directory),
    language: "Python",
    framework,
    manifest: marker.relative,
    aiPackages: AI_PACKAGES_PYTHON.filter((name) => lowered.includes(name)),
    dbPackages: ["psycopg", "pymysql", "sqlalchemy", "sqlite3", "pyodbc", "asyncpg"].filter((name) => lowered.includes(name)),
    isWorkspaceRoot: false
  };
}

async function describeDotnetProject(root, marker) {
  const raw = (await readText(marker.file)) || "";
  const packages = [...raw.matchAll(/PackageReference\s+Include="([^"]+)"/g)].map((match) => match[1]);
  const targetFramework = raw.match(/<TargetFramework[^>]*>([^<]+)</)?.[1]?.trim();
  const hasRazor = await exists(path.join(marker.directory, "Pages")) || raw.includes("Microsoft.NET.Sdk.Web");
  const framework = packages.some((name) => name.startsWith("Microsoft.AspNetCore")) || hasRazor
    ? "ASP.NET Core"
    : packages.some((name) => name.includes("Blazor")) ? "Blazor" : ".NET";
  return {
    kind: "dotnet",
    name: path.basename(marker.file, path.extname(marker.file)),
    directory: marker.directory,
    relative: relativePath(root, marker.directory),
    language: marker.kind === "csharp" ? "C#" : ".NET",
    framework: targetFramework ? `${framework} (${targetFramework})` : framework,
    manifest: marker.relative,
    aiPackages: packages.filter((name) => AI_PACKAGES_DOTNET.some((candidate) => name.startsWith(candidate))),
    dbPackages: packages.filter((name) => /EntityFrameworkCore|SqlClient|Dapper|Npgsql|MySqlConnector/i.test(name)),
    isWorkspaceRoot: false
  };
}

async function describeGenericProject(root, marker, language, framework) {
  const raw = (await readText(marker.file)) || "";
  const lowered = raw.toLowerCase();
  return {
    kind: marker.kind,
    name: path.basename(marker.directory),
    directory: marker.directory,
    relative: relativePath(root, marker.directory),
    language,
    framework,
    manifest: marker.relative,
    aiPackages: ["anthropic", "openai", "langchain", "ollama"].filter((name) => lowered.includes(name)),
    dbPackages: [],
    isWorkspaceRoot: false
  };
}

async function describe(root, marker) {
  switch (marker.kind) {
    case "node": return describeNodeProject(root, marker);
    case "python": return describePythonProject(root, marker);
    case "csharp":
    case "dotnet": return describeDotnetProject(root, marker);
    case "go": return describeGenericProject(root, marker, "Go", "Go");
    case "rust": return describeGenericProject(root, marker, "Rust", "Rust");
    case "ruby": return describeGenericProject(root, marker, "Ruby", "Ruby");
    case "php": return describeGenericProject(root, marker, "PHP", "PHP");
    case "java": return describeGenericProject(root, marker, "Java", "JVM");
    default: return null;
  }
}

/**
 * Discover every scannable project under `root`. In a monorepo this returns one entry
 * per package, service, or `.csproj` so the caller can present a picker grouped by stack.
 * A directory holding several markers (e.g. `pyproject.toml` + `requirements.txt`)
 * collapses to one project, keeping the richer manifest.
 */
export async function detectProjects(root) {
  const markers = await collectMarkers(root);
  const byDirectory = new Map();
  for (const marker of markers) {
    // Multiple .csproj files in one directory are genuinely separate projects; other
    // markers describing the same directory are duplicates of a single project.
    const key = marker.kind === "csharp" || marker.kind === "dotnet" ? marker.file : marker.directory;
    const existing = byDirectory.get(key);
    if (existing && rank(existing.kind) <= rank(marker.kind)) continue;
    byDirectory.set(key, marker);
  }

  const projects = [];
  for (const marker of byDirectory.values()) {
    const described = await describe(root, marker);
    if (described) projects.push(described);
  }

  projects.sort((a, b) => (a.relative === "." ? -1 : b.relative === "." ? 1 : a.relative.localeCompare(b.relative)));
  return projects;
}

function rank(kind) {
  const order = ["node", "csharp", "dotnet", "python", "go", "rust", "ruby", "php", "java"];
  const index = order.indexOf(kind);
  return index === -1 ? order.length : index;
}

/** Group projects by framework for the interactive picker. */
export function groupByStack(projects) {
  const groups = new Map();
  for (const project of projects) {
    const key = `${project.language} · ${project.framework}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(project);
  }
  return [...groups.entries()]
    .map(([stack, members]) => ({ stack, projects: members }))
    .sort((a, b) => b.projects.length - a.projects.length || a.stack.localeCompare(b.stack));
}

/**
 * Which optional rule packs apply to a project. Rules outside this set are reported as
 * gated rather than silently skipped, so a quiet scan is never mistaken for a clean one.
 */
export function capabilitiesOf(project) {
  return {
    ai: project.aiPackages.length > 0,
    database: project.dbPackages.length > 0,
    web: /Next|Nuxt|Remix|Express|Fastify|Koa|Hono|ASP\.NET|Django|Flask|FastAPI|NestJS|Blazor/i.test(project.framework)
  };
}

/** Detect agent instruction files, which get their own rule pack. */
export async function findAgentContextFiles(root) {
  const candidates = [
    "CLAUDE.md", "AGENTS.md", "AGENT.md", ".cursorrules", "GEMINI.md",
    ".github/copilot-instructions.md", ".windsurfrules"
  ];
  const found = [];
  for (const candidate of candidates) {
    const absolute = path.join(root, candidate);
    if (await exists(absolute)) found.push({ absolute, relative: candidate });
  }
  const rulesDirectory = path.join(root, ".cursor", "rules");
  if (await exists(rulesDirectory)) {
    for (const name of await readdir(rulesDirectory)) {
      if (name.endsWith(".mdc") || name.endsWith(".md")) {
        found.push({ absolute: path.join(rulesDirectory, name), relative: `.cursor/rules/${name}` });
      }
    }
  }
  const claudeAgents = path.join(root, ".claude", "agents");
  if (await exists(claudeAgents)) {
    for (const name of await readdir(claudeAgents)) {
      if (name.endsWith(".md")) {
        found.push({ absolute: path.join(claudeAgents, name), relative: `.claude/agents/${name}` });
      }
    }
  }
  return found;
}

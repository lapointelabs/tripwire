import { exec } from "node:child_process";
import { readFile } from "node:fs/promises";
import express from "express";
import { Pool } from "pg";

const app = express();
const pool = new Pool();

// EXPECT injection/sql-interpolation
app.get("/user", async (req, res) => {
  const rows = await pool.query(`SELECT * FROM users WHERE email = '${req.query.email}'`);
  res.json(rows);
});

// EXPECT injection/sql-interpolation (concatenation form)
async function findOrder(id) {
  return pool.query("SELECT * FROM orders WHERE id = " + id);
}

// SAFE: parameterized — must NOT be flagged
async function findOrderSafely(id) {
  return pool.query("SELECT * FROM orders WHERE id = $1", [id]);
}

// SAFE: tagged template that parameterizes — must NOT be flagged
const sql = String.raw;
async function findByTag(name) {
  return sql`SELECT * FROM tags WHERE name = ${name}`;
}

// EXPECT injection/command-execution
app.post("/backup", (req, res) => {
  exec(`tar -czf /tmp/out.tgz ${req.body.directory}`, (error) => res.end(String(error)));
});

// EXPECT injection/path-traversal
app.get("/file", async (req, res) => {
  const contents = await readFile(`/srv/data/${req.query.name}`, "utf8");
  res.send(contents);
});

// EXPECT web/raw-html-sink
app.get("/profile", (req, res) => {
  document.getElementById("bio").innerHTML = req.query.bio;
});

// EXPECT web/disabled-tls-verification
const agentOptions = { rejectUnauthorized: false };

// EXPECT web/permissive-cors
app.use(cors({ origin: "*", credentials: true }));

// EXPECT injection/dynamic-code-execution
function computeRule(expression) {
  return eval(expression);
}

export { findOrder, findOrderSafely, findByTag, computeRule, agentOptions };

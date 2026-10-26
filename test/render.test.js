"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { mask } = require("../dist/detectors");
const { renderReport, countByType } = require("../dist/report");
const { renderPlan, renderReplacements, riskyFiles } = require("../dist/plan");
const { fakes } = require("./fakes");

function finding(type, value, extra = {}) {
  return { commit: "a".repeat(40), file: "src/a.ts", line: 3, type, value, preview: mask(type, value), ...extra };
}

const F = [
  finding("aws-access-key", fakes.aws()),
  finding("github-token", fakes.github()),
  finding("email", "alice@corpmail.test"),
  finding("private-path", "/home/alice"),
  finding("private-key", fakes.keyHeader(), { file: "keys/id_rsa" }),
  finding("env-file", "", { file: ".env", line: null, preview: ".env" }),
  finding("aws-access-key", fakes.aws(), { file: "src/b.ts" }),
];

test("countByType counts per type", () => {
  assert.deepEqual(countByType(F)["aws-access-key"], 2);
  assert.deepEqual(countByType([]), {});
});

test("renderReport shows masked previews and never the full value", () => {
  const r = renderReport("../repo", F);
  assert.match(r, /Findings: 7\./);
  assert.match(r, /\| aws-access-key \| 2 \|/);
  assert.match(r, /\| `aaaaaaa` \| `src\/a.ts` \| 3 \| aws-access-key \| `AKIA\*\*\*\*` \|/);
  assert.match(r, /\| `\.env` \| - \| env-file \|/);
  for (const f of F) if (f.value && f.type !== "private-key") assert.ok(!r.includes(f.value), f.type);
});

test("renderReport escapes pipes and backticks in cells", () => {
  const r = renderReport("r", [finding("email", "a@b.test", { file: "we|ird`name" })]);
  assert.ok(r.includes("`we\\|ird'name`"));
});

test("renderReport says so when there are no findings", () => {
  assert.match(renderReport("r", []), /No findings\./);
});

test("renderReplacements lists each value once, longest first, without key headers or env files", () => {
  const out = renderReplacements(F);
  const lines = out.trimEnd().split("\n");
  assert.equal(lines.length, 4);
  const lens = lines.map((l) => l.split("==>")[0].length);
  assert.deepEqual(lens, [...lens].sort((a, b) => b - a));
  assert.ok(lines.includes(`${fakes.aws()}==>REDACTED`));
  assert.ok(lines.includes("alice@corpmail.test==>redacted@example.com"));
  assert.ok(lines.includes("/home/alice==>/home/<user>"));
  assert.ok(!out.includes("PRIVATE KEY"));
  assert.equal(renderReplacements([]), "");
});

test("riskyFiles lists env files and private-key files once, sorted", () => {
  assert.deepEqual(riskyFiles([...F, ...F]), [".env", "keys/id_rsa"]);
});

test("renderPlan lists rotations and file removals but no secret values", () => {
  const p = renderPlan("../repo", F, "/tmp/out/replacements.txt");
  assert.match(p, /Findings: 7 \(4 secret-like\)/);
  assert.match(p, /- \[ \] aws-access-key: rotate/);
  assert.match(p, /git filter-repo --replace-text '\/tmp\/out\/replacements.txt'/);
  assert.match(p, /git filter-repo --path '\.env' --path 'keys\/id_rsa' --invert-paths/);
  for (const f of F) if (f.value && f.type !== "private-key") assert.ok(!p.includes(f.value), f.type);
});

test("renderPlan shell-quotes paths with single quotes", () => {
  const p = renderPlan("r", [finding("env-file", "", { file: "it's/.env" })], "repl.txt");
  assert.ok(p.includes(`--path 'it'\\''s/.env'`));
});

test("renderPlan without secrets says so and drops the invert-paths step", () => {
  const p = renderPlan("r", [finding("email", "alice@corpmail.test")], "repl.txt");
  assert.match(p, /No secret-like findings/);
  assert.ok(!p.includes("--invert-paths"));
});

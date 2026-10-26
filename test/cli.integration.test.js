"use strict";
// End-to-end: build a throwaway git repo with fake secrets spread across branches, a tag-only
// commit and a .env file, run the built CLI, and check findings and that nothing leaks.
const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fakes } = require("./fakes");

const CLI = path.join(__dirname, "..", "dist", "cli.js");
const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "Test", GIT_AUTHOR_EMAIL: "test@example.com",
  GIT_COMMITTER_NAME: "Test", GIT_COMMITTER_EMAIL: "test@example.com",
  GIT_CONFIG_NOSYSTEM: "1", HOME: os.tmpdir(),
};

const SECRETS = {
  aws: fakes.aws(11),
  github: fakes.github(12),
  openai: fakes.openai(13),
  slack: fakes.slack(14),
  envValue: fakes.entropy(15),
  tagOnly: fakes.anthropic(16),
  email: "dana.lee@corpmail.test",
  path: "/home/dana",
};

function git(cwd, ...args) {
  return execFileSync("git", ["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", ...args], {
    cwd, env: GIT_ENV, encoding: "utf8",
  });
}

function commit(repo, files, msg) {
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true });
    fs.writeFileSync(path.join(repo, name), body);
  }
  git(repo, "add", "--", ...Object.keys(files));
  git(repo, "commit", "-q", "-m", msg);
}

function makeRepo(root) {
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);
  git(repo, "init", "-q");
  commit(repo, { "README.md": "# demo\nMaintainer: 1+bot@users.noreply.github.com\n" }, "init");
  // Secret added, then removed: only history still has it.
  commit(repo, { "config.js": `module.exports = { aws: "${SECRETS.aws}" };\n` }, "add config");
  commit(repo, { "config.js": "module.exports = { aws: process.env.AWS_KEY };\n" }, "remove key");
  commit(repo, { ".env": `API_SECRET=${SECRETS.envValue}\n`, ".env.example": "API_SECRET=changeme\n" }, "env");
  git(repo, "rm", "-q", "--cached", ".env");
  git(repo, "commit", "-q", "-m", "untrack env");
  // A feature branch with more leaks.
  git(repo, "checkout", "-q", "-b", "feature");
  commit(repo, {
    "scripts/deploy.sh": `#!/bin/sh\nexport GH_TOKEN=${SECRETS.github}\ncd ${SECRETS.path}/app\n`,
    "notes.txt": `contact ${SECRETS.email}\nslack ${SECRETS.slack}\nopenai ${SECRETS.openai}\n`,
    "keys/id_rsa": `${fakes.keyHeader()}\nnot-a-real-key-body\n`,
  }, "feature leaks");
  // A commit reachable only from a tag.
  git(repo, "checkout", "-q", "--detach", "main");
  commit(repo, { "release.txt": `ANTHROPIC_API_KEY=${SECRETS.tagOnly}\n` }, "release");
  git(repo, "tag", "v1.0.0");
  git(repo, "checkout", "-q", "main");
  return repo;
}

function run(repo, out, cmd) {
  return execFileSync(process.execPath, [CLI, cmd, repo, "--out", out], { encoding: "utf8", env: GIT_ENV });
}

test("scan and plan find leaks on every ref and never write a full secret", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hs-int-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = makeRepo(root);
  const out = path.join(root, "out");

  const scanOut = run(repo, out, "scan");
  const report = fs.readFileSync(path.join(out, "history-scrub-report.md"), "utf8");
  for (const [type, n] of Object.entries({
    "aws-access-key": 1, "github-token": 1, "openai-key": 1, "slack-token": 1, "anthropic-key": 1,
    "private-key": 1, "env-file": 2, email: 1, "private-path": 1, "high-entropy": 1,
  })) {
    assert.ok(scanOut.includes(`  ${type}: ${n}\n`), `${type}: ${n} missing from:\n${scanOut}`);
    assert.match(report, new RegExp(`\\| ${type} \\| ${n} \\|`));
  }
  assert.match(scanOut, /^Findings: 11$/m);
  assert.ok(!fs.existsSync(path.join(out, "replacements.txt")), "scan must not write replacements");
  assert.match(report, /`release.txt` \| 1 \| anthropic-key \| `sk-a\*\*\*\*`/);
  assert.match(report, /`\.env` \| - \| env-file/);
  assert.ok(!report.includes(".env.example"));
  assert.ok(!report.includes("noreply"));

  const planOut = run(repo, out, "plan");
  const plan = fs.readFileSync(path.join(out, "history-scrub-plan.md"), "utf8");
  const replPath = path.join(out, "replacements.txt");
  const repl = fs.readFileSync(replPath, "utf8");
  assert.match(plan, /--path '\.env' --path 'keys\/id_rsa' --invert-paths/);
  assert.match(planOut, /WARNING: replacements.txt contains the full secrets/);

  for (const [name, value] of Object.entries(SECRETS)) {
    for (const [where, text] of [["scan stdout", scanOut], ["report", report], ["plan stdout", planOut], ["plan", plan]]) {
      assert.ok(!text.includes(value), `${name} leaked into ${where}`);
    }
    assert.ok(repl.includes(`${value}==>`), `${name} missing from replacements.txt`);
  }
  if (process.platform !== "win32") assert.equal(fs.statSync(replPath).mode & 0o777, 0o600);
});

test("scan reads real git headers for odd file names and '++' lines", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hs-names-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);
  git(repo, "init", "-q");
  const files = { "my b/c.txt": `x\n++ ${SECRETS.aws}\n`, "caf\u00e9/.env": "S=1\n" };
  if (process.platform !== "win32") files['q"t/.env'] = "S=1\n";
  commit(repo, files, "odd names");
  const out = path.join(root, "out");
  run(repo, out, "scan");
  const report = fs.readFileSync(path.join(out, "history-scrub-report.md"), "utf8");
  assert.match(report, /`my b\/c.txt` \| 2 \| aws-access-key/);
  assert.match(report, /`caf\u00e9\/\.env` \| - \| env-file/);
  if (process.platform !== "win32") assert.match(report, /`q"t\/\.env` \| - \| env-file/);
});

test("plan rewrites an existing world-readable replacements.txt as 0600", { skip: process.platform === "win32" }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hs-mode-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);
  git(repo, "init", "-q");
  commit(repo, { "a.txt": `k=${SECRETS.aws}\n` }, "leak");
  const out = path.join(root, "out");
  fs.mkdirSync(out);
  const replPath = path.join(out, "replacements.txt");
  fs.writeFileSync(replPath, "stale\n", { mode: 0o644 });
  fs.chmodSync(replPath, 0o644);
  run(repo, out, "plan");
  assert.equal(fs.statSync(replPath).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(replPath, "utf8"), `${SECRETS.aws}==>REDACTED\n`);
});

test("scan of a path that is not a git repo exits 1 with a clear message", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-nogit-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const r = require("node:child_process").spawnSync(process.execPath, [CLI, "scan", dir, "--out", dir], {
    encoding: "utf8", env: { ...GIT_ENV, GIT_CEILING_DIRECTORIES: path.dirname(dir) },
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /is it a git repo\?/);
});

test("unknown commands and options exit 2 with usage", () => {
  for (const args of [["frobnicate"], ["scan", "--bogus"], []]) {
    const r = require("node:child_process").spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
    assert.equal(r.status, 2, args.join(" "));
    assert.match(r.stderr, /Commands:/);
  }
});

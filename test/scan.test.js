"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { BUILTIN } = require("../dist/detectors");
const { isEnvFile, isLockfile, scanLog } = require("../dist/scan");
const { fakes } = require("./fakes");

const MARK = "__HISTORY_SCRUB_COMMIT__";
const C1 = "1".repeat(40);
const C2 = "2".repeat(40);

/** A small `git log -p -U0 --format=MARK %H` fixture. */
function fixture() {
  return [
    `${MARK} ${C2}`,
    "",
    "diff --git a/config/app.yml b/config/app.yml",
    "index 1111111..2222222 100644",
    "--- a/config/app.yml",
    "+++ b/config/app.yml",
    "@@ -3 +3 @@ name: app",
    `-key: ${fakes.aws(9)}`,
    "+key: REDACTED",
    "@@ -10,0 +11,2 @@ db:",
    `+  token: ${fakes.github()}`,
    "+  owner: alice@corpmail.test",
    "diff --git a/.env b/.env",
    "deleted file mode 100644",
    "index 3333333..0000000",
    "--- a/.env",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    `-SECRET=${fakes.entropy()}`,
    `${MARK} ${C1}`,
    "",
    "diff --git a/.env b/.env",
    "new file mode 100644",
    "index 0000000..3333333",
    "--- /dev/null",
    "+++ b/.env",
    "@@ -0,0 +1 @@",
    `+SECRET=${fakes.entropy()}`,
    "diff --git a/.env.example b/.env.example",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/.env.example",
    "@@ -0,0 +1 @@",
    "+SECRET=changeme",
    "diff --git a/logo.png b/logo.png",
    "new file mode 100644",
    "Binary files /dev/null and b/logo.png differ",
    "",
  ].join("\n");
}

test("isEnvFile matches .env files and skips templates", () => {
  for (const p of [".env", ".env.local", "app/.env.production"]) assert.ok(isEnvFile(p), p);
  for (const p of [".env.example", "x/.env.sample", ".env.template", "env", ".envrc", "my.env"]) {
    assert.ok(!isEnvFile(p), p);
  }
});

test("scanLog attributes findings to commit, file and new-side line", () => {
  const got = scanLog(fixture(), BUILTIN).map(({ commit, file, line, type }) => ({ commit, file, line, type }));
  assert.deepEqual(got, [
    { commit: C2, file: "config/app.yml", line: 11, type: "github-token" },
    { commit: C2, file: "config/app.yml", line: 12, type: "email" },
    { commit: C2, file: ".env", line: null, type: "env-file" },
    { commit: C1, file: ".env", line: null, type: "env-file" },
    { commit: C1, file: ".env", line: 1, type: "high-entropy" },
  ]);
});

test("scanLog ignores removed lines and keeps full values only in memory", () => {
  const findings = scanLog(fixture(), BUILTIN);
  assert.ok(!findings.some((f) => f.value === fakes.aws(9)), "removed line was scanned");
  const gh = findings.find((f) => f.type === "github-token");
  assert.equal(gh.value, fakes.github());
  assert.equal(gh.preview, "ghp_****");
  assert.equal(findings.find((f) => f.type === "env-file").value, "");
});

test("scanLog dedupes identical findings", () => {
  const log = fixture();
  assert.equal(scanLog(log + log, BUILTIN).length, scanLog(log, BUILTIN).length);
});

test("scanLog returns nothing for an empty log", () => {
  assert.deepEqual(scanLog("", BUILTIN), []);
});

test("isLockfile matches dependency lockfiles by base name", () => {
  for (const p of ["package-lock.json", "web/yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock"]) {
    assert.ok(isLockfile(p), p);
  }
  for (const p of ["package.json", "lock.json", "docs/package-lock.json.md"]) assert.ok(!isLockfile(p), p);
});

test("scanLog skips high-entropy in lockfiles but still runs named detectors there", () => {
  const hash = `sha512-${fakes.entropy(21)}/${fakes.entropy(22)}+${fakes.entropy(23)}==`;
  const body = [
    `+      "integrity": "${hash}",`,
    `+      "resolved": "https://registry.test/x.tgz?token=${fakes.github(24)}",`,
  ];
  const log = (file) => [`${MARK} ${C1}`, `diff --git a/${file} b/${file}`, "--- /dev/null", `+++ b/${file}`, "@@ -0,0 +1,2 @@", ...body].join("\n");
  assert.deepEqual(scanLog(log("package-lock.json"), BUILTIN).map((f) => f.type), ["github-token"]);
  assert.ok(scanLog(log("src/hashes.txt"), BUILTIN).some((f) => f.type === "high-entropy"));
});

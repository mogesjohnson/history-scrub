"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { BUILTIN, detectLine, mask, shannonEntropy, loadPatterns, ENTROPY_THRESHOLD } = require("../dist/detectors");
const { fakes } = require("./fakes");

const types = (line, detectors = BUILTIN) => detectLine(line, detectors).map((h) => h.type);

test("detects each built-in secret type", () => {
  const cases = {
    "aws-access-key": `aws_access_key_id = ${fakes.aws()}`,
    "github-token": `token: ${fakes.github()}`,
    "openai-key": `OPENAI_API_KEY=${fakes.openai()}`,
    "anthropic-key": `ANTHROPIC_API_KEY=${fakes.anthropic()}`,
    "slack-token": `SLACK=${fakes.slack()}`,
    "private-key": fakes.keyHeader(),
  };
  for (const [type, line] of Object.entries(cases)) {
    const hits = detectLine(line, BUILTIN);
    assert.equal(hits.length, 1, `${type}: ${JSON.stringify(hits.map((h) => h.type))}`);
    assert.equal(hits[0].type, type);
  }
});

test("anthropic keys are not also reported as openai keys", () => {
  assert.deepEqual(types(`k=${fakes.anthropic()}`), ["anthropic-key"]);
});

test("detects emails but skips noreply and example domains", () => {
  assert.deepEqual(types("contact alice.smith@corpmail.test now"), ["email"]);
  assert.deepEqual(types("Author: 12345+alice@users.noreply.github.com"), []);
  assert.deepEqual(types("from no-reply@service.test"), []);
  assert.deepEqual(types("from noreply@service.test"), []);
  assert.deepEqual(types("see jane@example.com or jo@example.org"), []);
});

test("detects private paths and skips generic user names", () => {
  const hit = detectLine("cd /home/alice/project", BUILTIN);
  assert.deepEqual(hit, [{ type: "private-path", value: "/home/alice" }]);
  assert.deepEqual(types("C:\\Users\\bob\\Desktop"), ["private-path"]);
  assert.deepEqual(types("/Users/carol/src"), ["private-path"]);
  assert.deepEqual(types("/home/runner/work"), []);
  assert.deepEqual(types("C:\\Users\\Public\\Documents"), []);
  assert.deepEqual(types("C:\\Users\\<user>\\AppData"), []);
});

test("shannonEntropy matches known values", () => {
  assert.equal(shannonEntropy("aaaa"), 0);
  assert.equal(shannonEntropy("ab"), 1);
  assert.equal(shannonEntropy("abcd"), 2);
});

test("high-entropy flags random mixed tokens and skips words, hex and short tokens", () => {
  const tok = fakes.entropy();
  assert.ok(shannonEntropy(tok) >= ENTROPY_THRESHOLD);
  assert.deepEqual(detectLine(`secret = "${tok}"`, BUILTIN), [{ type: "high-entropy", value: tok }]);
  assert.deepEqual(types("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), []);
  assert.deepEqual(types("commit 9fceb02d0ae598e95dc970b74767f19372d61af8"), []);
  assert.deepEqual(types("short Ab3xY9"), []);
  assert.deepEqual(types("thisIsAVeryLongCamelCaseIdentifierName1"), []);
});

test("a token caught by a named detector is not reported again as high-entropy", () => {
  assert.deepEqual(types(`t=${fakes.github()}`), ["github-token"]);
});

test("duplicate values on one line are reported once", () => {
  const k = fakes.aws();
  assert.equal(detectLine(`${k} ${k}`, BUILTIN).length, 1);
});

test("mask never reveals more than four leading characters", () => {
  const aws = fakes.aws();
  assert.equal(mask("aws-access-key", aws), "AKIA****");
  assert.equal(mask("github-token", fakes.github()), "ghp_****");
  assert.equal(mask("high-entropy", "abcdefgh"), "ab****");
  assert.equal(mask("high-entropy", "abc"), "****");
  assert.equal(mask("email", "jane.doe@corpmail.test"), "j***@corpmail.test");
  assert.equal(mask("private-path", "C:\\Users\\jane"), "C:\\Users\\j****");
  assert.equal(mask("private-path", "/home/jane"), "/home/j****");
  assert.equal(mask("private-key", fakes.keyHeader()), "-----BEGIN ****PRIVATE KEY-----");
  for (const v of [aws, fakes.github(), fakes.openai(), fakes.slack(), fakes.entropy()]) {
    const m = mask("x", v);
    assert.ok(!m.includes(v.slice(0, 5)), `${m} leaks too much`);
  }
});

test("loadPatterns reads named and unnamed regexes and skips comments", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-pat-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "patterns.txt");
  fs.writeFileSync(file, "# comment\n\nticket: INTERNAL-[0-9]+\r\n[a-z0-9-]+\\.corp\\.internal\n");
  const ds = loadPatterns(file);
  assert.deepEqual(ds.map((d) => d.name), ["ticket", "custom-4"]);
  const hits = detectLine("see INTERNAL-42 on build-01.corp.internal", [...BUILTIN, ...ds]);
  assert.deepEqual(hits, [
    { type: "ticket", value: "INTERNAL-42" },
    { type: "custom-4", value: "build-01.corp.internal" },
  ]);
});

test("loadPatterns reports the file and line of an invalid regex", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-pat-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "bad.txt");
  fs.writeFileSync(file, "ok: abc\nbad: (unclosed\n");
  assert.throws(() => loadPatterns(file), (e) => e.message.startsWith(`${file}:2: invalid regex`));
});

test("custom patterns that can match the empty string report only real matches", () => {
  const tok = fakes.entropy(41);
  const hits = detectLine(`id=ab tok=${tok}`, [{ name: "maybe-ab", regex: /(?:ab)*/g }, ...BUILTIN]);
  assert.deepEqual(hits, [{ type: "maybe-ab", value: "ab" }, { type: "high-entropy", value: tok }]);
});

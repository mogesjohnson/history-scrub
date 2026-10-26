import { execFileSync } from "child_process";
import { Detector, detectLine, mask } from "./detectors";

export interface Finding {
  commit: string;
  file: string;
  line: number | null;
  type: string;
  preview: string;
  /** Full sensitive value. Kept in memory only; never printed or written to the report. */
  value: string;
}

const MARK = "__HISTORY_SCRUB_COMMIT__";

export function isEnvFile(path: string): boolean {
  const base = path.split("/").pop() || "";
  return /^\.env(\..+)?$/.test(base) && !/\.(example|sample|template)$/.test(base);
}

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
  "Cargo.lock", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum",
]);

/** Dependency lockfiles: their integrity hashes look random, so high-entropy is skipped there. */
export function isLockfile(path: string): boolean {
  return LOCKFILES.has(path.split("/").pop() || "");
}

export function gitLog(repo: string): string {
  return execFileSync(
    "git",
    [
      "-C", repo, "-c", "core.quotePath=false",
      "log", "-p", "--all", "-U0", "--no-color", "--no-ext-diff", "--no-renames", `--format=${MARK} %H`,
    ],
    { maxBuffer: 1024 * 1024 * 1024, encoding: "utf8" },
  );
}

/** Undo git's C-style path quoting (`"a\\"b"`, octal `\\303\\251` bytes). */
function unquote(q: string): string {
  const bytes: number[] = [];
  const simple: Record<string, string> = { a: "\x07", b: "\b", t: "\t", n: "\n", v: "\v", f: "\f", r: "\r" };
  for (let i = 0; i < q.length; i++) {
    const ch = q[i];
    if (ch !== "\\") { bytes.push(...Buffer.from(ch, "utf8")); continue; }
    const next = q[++i];
    if (/[0-7]/.test(next)) { bytes.push(parseInt(q.slice(i, i + 3), 8)); i += 2; }
    else bytes.push(...Buffer.from(simple[next] ?? next, "utf8"));
  }
  return Buffer.from(bytes).toString("utf8");
}

/**
 * Path from a `diff --git a/P b/P` header. With --no-renames both sides are the same path,
 * so split in the middle; this survives spaces and " b/" inside names. Quoted paths are unquoted.
 */
export function diffPath(header: string): string {
  const rest = header.slice("diff --git ".length);
  if (rest.startsWith('"')) {
    const m = /^"a\/(.*)" "b\/\1"$/.exec(rest);
    return m ? unquote(m[1]) : "";
  }
  const half = (rest.length - 5) / 2;
  if (!Number.isInteger(half) || !rest.startsWith("a/") || rest.slice(half + 2, half + 5) !== " b/") return "";
  return rest.slice(2, 2 + half);
}

/** Parse `git log -p` output and run detectors over every added line. */
export function scanLog(log: string, detectors: Detector[]): Finding[] {
  const found = new Map<string, Finding>();
  const add = (f: Finding) => {
    const key = [f.commit, f.file, f.line, f.type, f.value].join("\0");
    if (!found.has(key)) found.set(key, f);
  };
  let commit = "";
  let file = "";
  let lineNo = 0;
  let inHeader = false; // between "diff --git" and the first hunk: "---"/"+++" are file names
  for (const raw of log.split("\n")) {
    if (raw.startsWith(MARK)) {
      commit = raw.slice(MARK.length + 1).trim();
      file = "";
      inHeader = false;
      continue;
    }
    if (raw.startsWith("diff --git ")) {
      file = diffPath(raw);
      inHeader = true;
      if (file && isEnvFile(file)) {
        add({ commit, file, line: null, type: "env-file", preview: file, value: "" });
      }
      continue;
    }
    if (inHeader && (raw.startsWith("+++ ") || raw.startsWith("--- "))) continue;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      lineNo = parseInt(hunk[1], 10);
      inHeader = false;
      continue;
    }
    if (!inHeader && raw.startsWith("+")) {
      for (const h of detectLine(raw.slice(1), detectors, { entropy: !isLockfile(file) })) {
        add({ commit, file, line: lineNo, type: h.type, value: h.value, preview: mask(h.type, h.value) });
      }
      lineNo++;
    }
  }
  return [...found.values()];
}

export function scanRepo(repo: string, detectors: Detector[]): Finding[] {
  return scanLog(gitLog(repo), detectors);
}

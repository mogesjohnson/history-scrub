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

export function gitLog(repo: string): string {
  return execFileSync(
    "git",
    ["-C", repo, "log", "-p", "--all", "-U0", "--no-color", "--no-ext-diff", "--no-renames", `--format=${MARK} %H`],
    { maxBuffer: 1024 * 1024 * 1024, encoding: "utf8" },
  );
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
  for (const raw of log.split("\n")) {
    if (raw.startsWith(MARK)) {
      commit = raw.slice(MARK.length + 1).trim();
      file = "";
      continue;
    }
    if (raw.startsWith("diff --git ")) {
      const m = / b\/(.*)$/.exec(raw);
      file = m ? m[1] : "";
      if (file && isEnvFile(file)) {
        add({ commit, file, line: null, type: "env-file", preview: file, value: "" });
      }
      continue;
    }
    if (raw.startsWith("+++ ") || raw.startsWith("--- ")) continue;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      lineNo = parseInt(hunk[1], 10);
      continue;
    }
    if (raw.startsWith("+")) {
      for (const h of detectLine(raw.slice(1), detectors)) {
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

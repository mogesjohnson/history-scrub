import * as fs from "fs";

export interface Detector {
  name: string;
  regex: RegExp;
  /** Which capture group holds the sensitive value (default 0). */
  group?: number;
  /** Optional filter: return false to drop a match. */
  keep?: (value: string) => boolean;
}

export interface Hit {
  type: string;
  value: string;
}

const NOREPLY = /(noreply|no-reply)/i;
const EXAMPLE_DOMAINS = /@(example\.(com|org|net)|localhost)$/i;
const GENERIC_USERS = new Set(["user", "username", "name", "<user>", "<name>", "me", "you", "runner", "public", "shared", "default"]);

export const BUILTIN: Detector[] = [
  { name: "private-key", regex: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g },
  { name: "aws-access-key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  { name: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: "openai-key", regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  {
    name: "private-path",
    regex: /(?:\b[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}|\/home\/|\/Users\/)([A-Za-z0-9][A-Za-z0-9._-]*)/g,
    keep: (v) => !GENERIC_USERS.has(lastSegment(v).toLowerCase()),
  },
  {
    name: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    keep: (v) => !NOREPLY.test(v) && !EXAMPLE_DOMAINS.test(v),
  },
];

function lastSegment(path: string): string {
  const parts = path.split(/[\\/]+/);
  return parts[parts.length - 1] || "";
}

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const TOKEN = /[A-Za-z0-9+_-]{24,}={0,2}/g;
export const ENTROPY_THRESHOLD = 4.5;

function highEntropy(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(TOKEN)) {
    const t = m[0];
    // Needs a mix of character classes; skips paths, words and plain hex hashes.
    if (!/[0-9]/.test(t) || !/[A-Z]/.test(t) || !/[a-z]/.test(t)) continue;
    if (shannonEntropy(t) >= ENTROPY_THRESHOLD) out.push(t);
  }
  return out;
}

/** Parse a pattern file: one regex per line, optionally "name: regex". '#' starts a comment. */
export function loadPatterns(file: string): Detector[] {
  const out: Detector[] = [];
  fs.readFileSync(file, "utf8").split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const m = /^([A-Za-z0-9_.-]+):\s+(.+)$/.exec(line);
    const name = m ? m[1] : `custom-${i + 1}`;
    const src = m ? m[2] : line;
    try {
      out.push({ name, regex: new RegExp(src, "g") });
    } catch (e) {
      throw new Error(`${file}:${i + 1}: invalid regex (${(e as Error).message})`);
    }
  });
  return out;
}

/**
 * Run detectors over one line. Pass `entropy: false` to skip the high-entropy check
 * (used for lockfiles, whose integrity hashes are random by design and not secrets).
 */
export function detectLine(line: string, detectors: Detector[], opts: { entropy?: boolean } = {}): Hit[] {
  const hits: Hit[] = [];
  const seen = new Set<string>();
  for (const d of detectors) {
    for (const m of line.matchAll(d.regex)) {
      const value = m[0];
      // A custom pattern such as `x*` can match the empty string; that is never a finding
      // (and an empty "seen" value would hide every high-entropy token on the line).
      if (!value) continue;
      if (d.keep && !d.keep(value)) continue;
      if (seen.has(value)) continue;
      seen.add(value);
      hits.push({ type: d.name, value });
    }
  }
  if (opts.entropy === false) return hits;
  for (const t of highEntropy(line)) {
    if ([...seen].some((s) => s.includes(t) || t.includes(s))) continue;
    seen.add(t);
    hits.push({ type: "high-entropy", value: t });
  }
  return hits;
}

/** Mask a sensitive value. Never returns more than a few leading characters. */
export function mask(type: string, value: string): string {
  if (type === "private-key") return "-----BEGIN ****PRIVATE KEY-----";
  if (type === "email") {
    const [local, domain] = value.split("@");
    return `${local.slice(0, 1)}***@${domain}`;
  }
  if (type === "private-path") {
    const name = lastSegment(value);
    return value.slice(0, value.length - name.length) + name.slice(0, 1) + "****";
  }
  const keep = Math.min(4, Math.floor(value.length / 4));
  return value.slice(0, keep) + "****";
}

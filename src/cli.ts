#!/usr/bin/env node
import * as fs from "fs";
import * as path from "path";
import { BUILTIN, Detector, loadPatterns } from "./detectors";
import { renderPlan, renderReplacements } from "./plan";
import { countByType, renderReport } from "./report";
import { Finding, scanRepo } from "./scan";

const USAGE = `history-scrub <command> [repo-path] [options]

Commands:
  scan [repo-path]   Scan every commit on every branch and tag; write history-scrub-report.md
  plan [repo-path]   Scan, then write history-scrub-plan.md and replacements.txt

Options:
  --patterns <file>  Extra detectors, one regex per line, optionally "name: regex"
  --out <dir>        Where to write output files (default: current directory)
  -h, --help         Show this help

Nothing is ever printed unmasked, and history-scrub never rewrites or pushes.
`;

interface Args { cmd: string; repo: string; patterns?: string; out: string }

function parseArgs(argv: string[]): Args {
  const rest: string[] = [];
  let patterns: string | undefined;
  let out = ".";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") { process.stdout.write(USAGE); process.exit(0); }
    else if (a === "--patterns") patterns = argv[++i];
    else if (a === "--out") out = argv[++i];
    else if (a.startsWith("-")) fail(`unknown option ${a}`);
    else rest.push(a);
  }
  const [cmd, repo = "."] = rest;
  if (cmd !== "scan" && cmd !== "plan") fail(cmd ? `unknown command ${cmd}` : "missing command");
  if (patterns === undefined && argv.includes("--patterns")) fail("--patterns needs a file");
  return { cmd, repo, patterns, out };
}

function fail(msg: string): never {
  process.stderr.write(`history-scrub: ${msg}\n\n${USAGE}`);
  process.exit(2);
}

function summary(findings: Finding[]): void {
  const counts = countByType(findings);
  process.stdout.write(`Findings: ${findings.length}\n`);
  for (const [t, n] of Object.entries(counts).sort()) process.stdout.write(`  ${t}: ${n}\n`);
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const repo = path.resolve(args.repo);
  if (!fs.existsSync(repo)) fail(`no such path ${repo}`);
  let detectors: Detector[] = BUILTIN;
  if (args.patterns) detectors = [...BUILTIN, ...loadPatterns(args.patterns)];
  let findings: Finding[];
  try {
    findings = scanRepo(repo, detectors);
  } catch (e) {
    process.stderr.write(`history-scrub: git log failed in ${repo}: is it a git repo?\n`);
    process.exit(1);
  }
  fs.mkdirSync(args.out, { recursive: true });
  const reportPath = path.join(args.out, "history-scrub-report.md");
  fs.writeFileSync(reportPath, renderReport(args.repo, findings));
  summary(findings);
  process.stdout.write(`Wrote ${reportPath} (masked)\n`);
  if (args.cmd === "plan") {
    const replPath = path.join(args.out, "replacements.txt");
    const planPath = path.join(args.out, "history-scrub-plan.md");
    // `mode` only applies when the file is created, so remove any old copy first: an existing
    // 0644 replacements.txt would otherwise keep its mode while receiving the full secrets.
    fs.rmSync(replPath, { force: true });
    fs.writeFileSync(replPath, renderReplacements(findings), { mode: 0o600, flag: "wx" });
    fs.writeFileSync(planPath, renderPlan(args.repo, findings, path.resolve(replPath)));
    process.stdout.write(`Wrote ${planPath}\n`);
    process.stdout.write(
      `Wrote ${replPath}\n  WARNING: replacements.txt contains the full secrets. Never commit or share it; delete it after use.\n`,
    );
  }
}

main();

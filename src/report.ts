import { Finding } from "./scan";

export function countByType(findings: Finding[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const f of findings) c[f.type] = (c[f.type] || 0) + 1;
  return c;
}

function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/`/g, "'");
}

/** Markdown report. Uses only masked previews; never the raw value. */
export function renderReport(repo: string, findings: Finding[]): string {
  const lines: string[] = [];
  lines.push("# history-scrub report", "");
  lines.push(`Repository: \`${repo}\``, "");
  lines.push(`Scanned: all branches and tags (\`git log -p --all\`). Findings: ${findings.length}.`, "");
  lines.push("Values are masked. Re-run locally to see where each one lives; full values are never written.", "");
  const counts = countByType(findings);
  if (findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n") + "\n";
  }
  lines.push("## Summary", "", "| Type | Count |", "| --- | --- |");
  for (const [t, n] of Object.entries(counts).sort()) lines.push(`| ${t} | ${n} |`);
  lines.push("", "## Findings", "", "| Commit | File | Line | Type | Preview |", "| --- | --- | --- | --- | --- |");
  for (const f of findings) {
    lines.push(
      `| \`${f.commit.slice(0, 7)}\` | \`${cell(f.file)}\` | ${f.line ?? "-"} | ${f.type} | \`${cell(f.preview)}\` |`,
    );
  }
  return lines.join("\n") + "\n";
}

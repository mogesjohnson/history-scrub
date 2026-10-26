import { Finding } from "./scan";

const SECRET_TYPES = new Set([
  "aws-access-key", "github-token", "openai-key", "anthropic-key", "slack-token", "private-key", "high-entropy",
]);

function replacementFor(f: Finding): string {
  if (f.type === "email") return "redacted@example.com";
  if (f.type === "private-path") return f.value.replace(/[^\\/]+$/, "<user>");
  return "REDACTED";
}

/**
 * Lines for `git filter-repo --replace-text`. CONTAINS FULL SECRETS: write it locally
 * with mode 0600 and never commit it. Private-key headers are skipped (the key body
 * is what matters; remove such files with --invert-paths instead).
 */
export function renderReplacements(findings: Finding[]): string {
  const seen = new Map<string, string>();
  for (const f of findings) {
    if (!f.value || f.type === "env-file" || f.type === "private-key") continue;
    if (!seen.has(f.value)) seen.set(f.value, replacementFor(f));
  }
  // Longest first so a value contained in another is replaced after the longer one.
  return [...seen.entries()]
    .sort((a, b) => b[0].length - a[0].length)
    .map(([v, r]) => `${v}==>${r}`)
    .join("\n") + (seen.size ? "\n" : "");
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function riskyFiles(findings: Finding[]): string[] {
  const files = new Set<string>();
  for (const f of findings) if (f.type === "env-file" || f.type === "private-key") files.add(f.file);
  return [...files].sort();
}

export function renderPlan(repo: string, findings: Finding[], replacementsPath: string): string {
  const live = findings.filter((f) => SECRET_TYPES.has(f.type));
  const kinds = [...new Set(live.map((f) => f.type))].sort();
  const drop = riskyFiles(findings);
  const pathArgs = drop.map((p) => `--path ${shellQuote(p)}`).join(" ");
  const L: string[] = [];
  L.push("# history-scrub cleanup plan", "");
  L.push(`Repository: \`${repo}\`. Findings: ${findings.length} (${live.length} secret-like).`, "");
  L.push("history-scrub never rewrites history or pushes. Every step below is for a human to run.", "");
  L.push("## 1. Rotate live credentials first", "");
  L.push("Rewriting history does not un-leak a secret: anyone who cloned or forked already has it.");
  L.push("Revoke and reissue every credential in the report before anything else.", "");
  if (kinds.length) for (const k of kinds) L.push(`- [ ] ${k}: rotate it in the provider console`);
  else L.push("- No secret-like findings. Still review emails and paths in the report.");
  L.push("", "## 2. Back up a mirror clone", "", "```sh");
  L.push("git clone --mirror <remote-url> repo-backup.git", "```", "");
  L.push("Keep the backup offline; it still contains the leaked values.", "");
  L.push("## 3. Rewrite history with git filter-repo", "");
  L.push(`\`${replacementsPath}\` holds \`literal==>REDACTED\` lines. **It contains the full secrets.**`);
  L.push("Do not commit it, paste it, or upload it. Delete it when you are done.", "");
  L.push("Work in a fresh clone (filter-repo refuses to run in a non-fresh one):", "", "```sh");
  L.push("git clone <remote-url> scrub && cd scrub");
  L.push(`git filter-repo --replace-text ${shellQuote(replacementsPath)}`);
  if (drop.length) L.push(`git filter-repo ${pathArgs} --invert-paths`);
  L.push("```", "");
  if (drop.length) {
    L.push("The second command removes these files from every commit:", "");
    for (const p of drop) L.push(`- \`${p}\``);
    L.push("");
  }
  L.push("Re-run `history-scrub scan .` in the rewritten clone and confirm the report is empty.", "");
  L.push("## 4. Force-push (human only, after review)", "", "```sh");
  L.push("git remote add origin <remote-url>   # filter-repo removes the remote");
  L.push("git push --force --all", "git push --force --tags", "```", "");
  L.push("Branch protection may need to be lifted for the push and restored right after.", "");
  L.push("## 5. Tell collaborators to re-clone", "");
  L.push("Old clones still hold the old history, and a merge from one reintroduces it.");
  L.push("Ask everyone to delete local clones and re-clone; do not pull or rebase onto the rewritten branches.", "");
  L.push("## 6. Clean up outside git", "");
  L.push("- GitHub keeps old commits reachable through PRs, PR bodies, review comments and cached views.");
  L.push("  Edit or delete PR bodies and comments that quote a value, then contact GitHub Support to purge");
  L.push("  cached views and dangling commits.");
  L.push("- Forks keep their own copy. Ask fork owners to delete or re-fork.");
  L.push("- Check CI logs, release assets, wikis, issues and package registries for the same values.");
  return L.join("\n") + "\n";
}

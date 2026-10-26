# history-scrub

Scan every commit of a git repository (all branches and tags) for leaked secrets and personal
info, write a **masked** report, and plan a `git filter-repo` cleanup for a human to run.

history-scrub never rewrites history, never pushes, and never prints a full secret.

## Install

```sh
git clone https://github.com/mogesjohnson/history-scrub && cd history-scrub
npm install        # dev dependency: typescript; builds dist/ via prepare
npm link           # optional: puts `history-scrub` on PATH
```

Node 18+ and `git` are required. There are no runtime dependencies.

## Usage

```sh
history-scrub scan [repo-path] [--patterns file] [--out dir]
history-scrub plan [repo-path] [--patterns file] [--out dir]
```

- `scan` runs `git log -p --all`, checks every added line, and writes `history-scrub-report.md`.
  The console shows counts by type only.
- `plan` also writes `history-scrub-plan.md` and `replacements.txt`.
  **`replacements.txt` contains the full secrets** (`literal==>REDACTED` lines for
  `git filter-repo --replace-text`). It is written with mode 0600 and is in `.gitignore`.
  Never commit or share it, and delete it when you are done.

### Detectors

| Type | What it matches |
| --- | --- |
| `private-path` | `C:\Users\<name>`, `/home/<name>`, `/Users/<name>` (generic names skipped) |
| `email` | email addresses, except `noreply` / `users.noreply.github.com` and `example.com` |
| `aws-access-key` | `AKIA...` / `ASIA...` |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `openai-key`, `anthropic-key` | `sk-...`, `sk-proj-...`, `sk-ant-...` |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `private-key` | `-----BEGIN ... PRIVATE KEY-----` blocks |
| `high-entropy` | mixed-case alphanumeric tokens of 24+ chars with Shannon entropy >= 4.5 |
| `env-file` | any `.env` / `.env.*` file touched in history (`.env.example` skipped) |
| custom | lines of `--patterns file`: one regex per line, optionally `name: regex`; `#` comments |

Example pattern file:

```text
# internal ticket ids
ticket: INTERNAL-[0-9]+
corp-host: [a-z0-9-]+\.corp\.internal
```

Findings are deduped by commit, file, line, type and value.

### Masking

Previews keep at most four leading characters: `AKIA****`, `ghp_****`, `j***@example.com`,
`C:\Users\j****`. Full values live only in memory and in the local `replacements.txt`.

## Example report

This example is illustrative. Every name, address and key in it is a placeholder.

```markdown
# history-scrub report

Repository: `../some-repo`

Scanned: all branches and tags (`git log -p --all`). Findings: 4.

## Summary

| Type | Count |
| --- | --- |
| aws-access-key | 1 |
| email | 1 |
| env-file | 1 |
| private-path | 1 |

## Findings

| Commit | File | Line | Type | Preview |
| --- | --- | --- | --- | --- |
| `1a2b3c4` | `scripts/test/hooks.test.mjs` | 1 | private-path | `C:\Users\<user>****` |
| `1a2b3c4` | `scripts/test-windows.ps1` | 109 | email | `j***@example.com` |
| `5d6e7f8` | `.env` | - | env-file | `.env` |
| `5d6e7f8` | `config/deploy.yml` | 12 | aws-access-key | `AKIA****` |
```

## The cleanup plan

`history-scrub-plan.md` walks a human through:

1. Rotate every live credential first. Rewriting history does not un-leak anything.
2. Back up a mirror clone (`git clone --mirror`).
3. In a fresh clone, run `git filter-repo --replace-text replacements.txt`, and
   `git filter-repo --path <file> --invert-paths` for `.env` and private-key files.
4. Re-scan, then force-push by hand: `git push --force --all` and `git push --force --tags`.
5. Tell collaborators to delete their clones and re-clone.
6. Clean up outside git: PR bodies, review comments, cached views and forks keep old content;
   GitHub Support can purge cached views and dangling commits.

## Development

```sh
npm run build
node dist/cli.js scan /path/to/repo --out /tmp/hs
npm test           # builds, then runs node:test suites in test/ (no extra dependencies)
```

Tests build fake credentials at runtime (`test/fakes.js`) so no token-shaped literal is committed.
CI (`.github/workflows/ci.yml`) runs `npm ci`, `npm run build` and `npm test` on Node 20.

Agent and contributor rules are in [AGENTS.md](AGENTS.md) and [RULES.md](RULES.md).

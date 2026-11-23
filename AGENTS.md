# NetScope

Local network discovery and mapping tool. Scans the local subnet (including
Atom and Apollo) to map active devices, open ports and service versions,
shown in a clean GUI.

## Rules
- Never push to main. Work on branches named `hermes/<topic>` and open a PR.
- Pull main before starting any new task: `git pull --ff-only`.
- Small PRs: one milestone or feature each, with tests.
- Every PR description must contain:
  1. A plain-language summary of what changed and why.
  2. How I can try it myself, with exact commands for Windows.
  3. The real test output you ran (pasted, not paraphrased).
  4. Anything you're unsure about or decided on your own.
- Never claim something is done or working without showing evidence.
- If a tool, credential or permission is missing, ask me. Never work
  around a restriction (no reading other processes' environments, no
  hunting for secrets outside this repo's scope).
- No secrets in the repo. Config goes in env vars or a gitignored file.
- Keep docs/ up to date: architecture, decisions, how to run.
- In every PR, update docs/STATUS.md (what's done, in progress, next
  steps, known issues) and record every decision I make in
  docs/decisions.md.

## Session start (every new session)
Before changing anything:
1. Read AGENTS.md, docs/STATUS.md and docs/decisions.md.
2. Run `git fetch --all` and `git pull --ff-only` on main. If continuing
   a branch, switch to it and pull.
3. Run `git status`, `git log --oneline -10`, `gh pr list`,
   `gh issue list`, and the tests.
4. Summarize the project state, the next step and any open questions,
   then wait for my confirmation.

## Handoff (when I ask for one, or when the session gets long)
1. Stop starting new work; finish or park the current task.
2. Commit and push everything (WIP is fine) so `git status` is clean.
3. Open or update the PR (draft if unfinished).
4. Update docs/STATUS.md and docs/decisions.md on the branch.
5. Update the relevant issues.
6. Post a short summary (branch, latest commit, PR, test status, next
   step, open questions) and the prompt for the new session.

## Project-specific rules
- Scanner logic must be testable without a network (mock nmap output).

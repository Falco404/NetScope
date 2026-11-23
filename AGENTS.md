# NetScope

Local network discovery and mapping tool. Scans the local subnet (including
Atom and Apollo) to map active devices, open ports and service versions,
shown in a clean GUI.

## Rules
- Pull main before starting any work.
- Never push to main. Work on branches named `hermes/<topic>` and open a PR.
- Small PRs, one feature each, with tests.
- Scanning is only allowed against private ranges (10.x, 172.16-31.x,
  192.168.x). Refuse any other target in the code itself.
- No secrets in the repo. Config goes in env vars or a gitignored file.
- Keep a docs/ folder with architecture and decisions up to date.
- Scanner logic must be testable without a network (mock nmap output).

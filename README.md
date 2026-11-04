<p align="center"><img src="assets/gatekeeper-icon-512.png" width="120" alt="Gatekeeper"></p>

# Gatekeeper

**A security crew of four AI agents that lives in your team chat and stops bad packages before anyone installs them.**

Coding agents write `npm install` and `pip install` lines all day. Sometimes the package they ask for **does not exist**: the model invented the name. Attackers watch for exactly those invented names and register them with malware inside ("slopsquatting"). The next developer, or the next coding agent, installs it.

Gatekeeper puts four agents into the room where that install line shows up. They are built on [Switch](https://github.com/sandbox-quantum/switch), so the same crew works in any chat Switch connects to (Discord today, Slack and others through the same Switch room).

## The crew

**Scout** reads every message in the room. When it sees an install command (npm, yarn, pnpm, bun, npx, pip, uv, poetry, pipenv), it checks each package live on npm or PyPI: does it exist, how old is it, how many downloads, how many versions, does it run a script on install, is it one typo away from a popular package.

**Inspector** opens any package Scout finds risky and reads its code. The archive is downloaded into memory and read as text. Nothing is installed, extracted to disk, imported or run. It looks for what real malware does: install hooks, code that goes online during install, machine and user details sent out, credentials and wallet files read, data sent to webhooks or data-collection services, decoded code being executed, shell commands, obfuscation.

**Squat Watch** keeps this team's private list of package names its agents invented. It checks npm and PyPI every 5 minutes, and the moment one of those names gets registered, it alerts the room and hands the new package to Inspector. It also counts how often a name comes back: a name your agents invent again and again is exactly the one an attacker will grab.

**Fixer** rewrites the install line into a safe one (the real package instead of the lookalike, invented names removed) and holds the human approval gate. A risky package is not silently blocked: a person in the room types `approve <name>`, Fixer records who approved it and when, and Scout shows that approval next time. Each room has its own rules.

## What it looks like

```
you:        npm i expres axios number-to-words-indian

Scout:      Stop: this install includes a package that does not exist.
            ⚠️ expres (npm): 14y old, 6,928 downloads/week, 5 versions. one typo away from `express`
            ✅ axios (npm): 12y old, 144,088,077 downloads/week, 147 versions.
            👻 number-to-words-indian (npm): does not exist. If anyone registers it later, it is a trap.

Fixer:      🔧 Safe version (`expres` → `express`, `number-to-words-indian` removed):
            npm i express axios

Squat Watch: 👀 number-to-words-indian (npm) is on this team's watchlist now.

Inspector:  🟢 expres@0.0.5: read 13 files, ran none. Nothing that steals, downloads or hides anything.
```

## Commands

Everything works by plain chat. Mention an agent to talk to it directly.

- Paste any install line, or a coding agent's answer that contains one. Scout checks it.
- `approve <name>`: allow a risky package in this room (your name is recorded).
- `@fixer rules`: show this room's rules and approvals.
- `@fixer rule min-age 60`: packages younger than 60 days need approval here.
- `@fixer rule install-scripts on`: anything that runs a script on install needs approval here.
- `@fixer revoke <name>`: take an approval back.
- `@inspector npm:left-pad` or `@inspector pypi:requests`: read any package on demand.
- `@squat-watch list`: names this team's agents invented, and how often.
- `@squat-watch npm:some-name`: watch a name by hand.

## How it works

```
 chat (Discord / Slack / ...)
            │
      Switch room  ◄── each agent has its own Switch identity and WebSocket connection
            │
   ┌────────┼────────────┬──────────────┐
 Scout   Inspector   Squat Watch      Fixer
   │         ▲            ▲              ▲
   └──── opens a case on the shared board ┘
```

- `gatekeeper/switch.py`: a small client for the Switch agent protocol (register, WebSocket events with ping/pong and reconnect, room messages, operations).
- `gatekeeper/crew.py`: the case board Scout opens and the others subscribe to, plus per-room rules and approvals stored on disk.
- `gatekeeper/registry.py`: live npm and PyPI checks, and the lookalike test (Damerau-Levenshtein against the top 3,000 packages of each ecosystem).
- `gatekeeper/inspect_pkg.py`: the in-memory archive reader and the rules.
- `gatekeeper/scout.py`, `inspector.py`, `squat_watch.py`, `fixer.py`: the four agents.

Each agent posts in the room as itself, so the team sees four voices, not one bot. They hand work to each other through the case board, so nobody parses another agent's prose.

## How well it works

We measured Inspector on **real malware** from Datadog's open [malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset) (packages removed from npm and PyPI after human triage) and on the **most popular real packages**. The rules were tuned on one set of samples; the numbers below come from samples that were held out until the end.

**npm:** of 200 malicious packages never seen during tuning, Inspector flagged **60%** (37% outright "malicious-looking"). Of 500 popular packages, it wrongly called **1 (0.2%)** malicious and asked for a human look on 0.8%.

**PyPI:** of 196 held-out malicious packages, it flagged **84%** (65% outright). Of 470 popular packages, it wrongly called 1.5% malicious and asked for a human look on 8.3%.

Full output: [`eval/RESULTS.md`](eval/RESULTS.md). Reproduce with `python -m eval.run_eval 200 500 500` (run it on a throwaway machine: the samples are real malware, read in memory only).

**What these numbers do not include.** Inspector only reads code. In real use, Scout also flags a package that is days old, has one version and almost no downloads, which describes most fresh malware. That check cannot be replayed on packages the registries have already removed, so it is not counted above. Many npm samples we missed contain no code at all beyond a manifest, and only that metadata would catch them.

## Run it

You need a Switch server (we run Switch 0.31.0 with Docker on a small cloud VM) and Python 3.11+.

```bash
git clone <this repo> && cd gatekeeper
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set SWITCH_API and a registration key from Switch Console
python register_crew.py         # registers scout, inspector, squat-watch, fixer (once)
python -u run_crew.py           # the crew connects and listens
```

Then, in your chat: invite each agent to the room (`!invite-agent @scout`, one per message, on Discord) and paste an install line.

## Safety

- Inspector never installs, extracts to disk, imports or runs a package. Archives are size-capped (25 MB download, 2 MB per file, 40 MB total read) so a zip bomb cannot hurt the host.
- Gatekeeper never installs anything for you. Fixer only proposes a command, and a person approves risky packages.
- The eval reads real malware samples in memory on a disposable VM, never on a developer machine.

## Built with

[Switch](https://github.com/sandbox-quantum/switch) for the rooms and agent identities, npm and PyPI public APIs, [npm-high-impact](https://github.com/wooorm/npm-high-impact) and [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) for the popular lists, and Datadog's dataset for the eval. Built by voice with Wispr Flow for Flip the Switch by WeMakeDevs.

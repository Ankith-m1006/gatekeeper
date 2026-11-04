<p align="center"><img src="assets/social-preview.png" alt="Gatekeeper: a security crew of four AI agents in your team chat, built on Switch"></p>

<p align="center">
  <a href="https://github.com/Ankith-m1006/gatekeeper/actions/workflows/tests.yml"><img src="https://github.com/Ankith-m1006/gatekeeper/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
  <img src="https://img.shields.io/badge/built%20on-Switch-1a1a1a" alt="built on Switch">
  <img src="https://img.shields.io/badge/python-3.11%2B-1a1a1a" alt="python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-1a1a1a" alt="MIT license">
</p>

# Gatekeeper

**A security crew of four AI agents that lives in your team chat and stops bad packages before anyone installs them.**

Coding agents write `npm install` and `pip install` lines all day. Sometimes the package they ask for **does not exist**: the model invented the name. Attackers watch for exactly those invented names and register them with malware inside ("slopsquatting"). The next developer, or the next coding agent, installs it.

Gatekeeper puts four agents into the room where that install line shows up. They are built on [Switch](https://github.com/sandbox-quantum/switch), so the same crew works in any chat Switch connects to (Discord today, Slack and others through the same Switch room).

## The crew

<p align="center">
  <img src="assets/scout.svg" width="96" alt="Scout">&nbsp;&nbsp;
  <img src="assets/inspector.svg" width="96" alt="Inspector">&nbsp;&nbsp;
  <img src="assets/squat-watch.svg" width="96" alt="Squat Watch">&nbsp;&nbsp;
  <img src="assets/fixer.svg" width="96" alt="Fixer">
  <br><sub><b>Scout</b> · <b>Inspector</b> · <b>Squat Watch</b> · <b>Fixer</b></sub>
</p>

**Scout** reads every message in the room. When it sees an install command (npm, yarn, pnpm, bun, npx, pip, uv, poetry, pipenv), it checks each package live on npm or PyPI: does it exist, how old is it, how many downloads, how many versions, does it run a script on install, is it one typo away from a popular package.

**Inspector** opens any package Scout finds risky and reads its code. The archive is downloaded into memory and read as text. Nothing is installed, extracted to disk, imported or run. It looks for what real malware does: install hooks, code that goes online during install, machine and user details sent out, credentials and wallet files read, data sent to webhooks or data-collection services, decoded code being executed, shell commands, obfuscation.

**Squat Watch** guards the names that don't exist yet. It keeps this team's list of package names its agents invented, checks npm and PyPI every 5 minutes, and the moment one gets registered it alerts the room and hands the new package to Inspector. It counts how often a name comes back: a name your agents invent again and again is exactly the one an attacker will grab. It also learns the real packages your team installs and reads the npm and PyPI new-package feeds every 2 minutes, so a brand-new lookalike (say `expresss`) is flagged before anyone asks for it.

**Fixer** rewrites the install line into a safe one (the real package instead of the lookalike, invented names removed) and holds the human approval gate. A risky package is not silently blocked: a person in the room types `approve <name>`, Fixer writes who approved it and when into the room's **Gatekeeper ledger** (a Switch room document), and Scout reads that ledger before every check. Each room has its own rules, and Fixer welcomes new people to the room with them.

## What it looks like

Real screenshots from our Discord room (a Switch room), in order: Scout checks the install and hands the case to the crew through Switch, the crew answers, Switch records their room documents, and Scout reads a person's approval back from the ledger.

<p align="center">
  <img src="assets/screens/handoff.jpg" width="24%" alt="Scout's verdict and the handoff to the crew">
  <img src="assets/screens/crew-replies.jpg" width="24%" alt="Squat Watch, Inspector and Fixer answer">
  <img src="assets/screens/room-documents.jpg" width="24%" alt="Switch shows the crew's room documents">
  <img src="assets/screens/approved.jpg" width="24%" alt="Scout shows the approval from the ledger">
</p>

The same flow as text:

```
you:          npm i expres axios number-to-words-indian

Scout:        Stop: this install includes a package that does not exist.
              ⚠️ expres (npm): 14y old, 6,928 downloads/week, 5 versions. one typo away from `express`
              ✅ axios (npm): 12y old, 144,088,077 downloads/week, 147 versions.
              👻 number-to-words-indian (npm): does not exist. If anyone registers it later, it is a trap.
              @inspector @squat-watch @fixer Over to the crew:
              • Inspector, read `npm:expres`
              • Squat Watch, watch `npm:number-to-words-indian`
              • Fixer, make this safe: npm i expres axios number-to-words-indian

Squat Watch:  👀 number-to-words-indian again: asked for 3 times. Something keeps inventing this name.
Inspector:    🟢 expres@0.0.5: read 13 files, ran none. Nothing that steals, downloads or hides anything.
Fixer:        🔧 Safe version (`expres` → `express`, `number-to-words-indian` removed):
              npm i express axios

you:          approve expres
Fixer:        ✅ `expres` approved for this room by you, written in the "Gatekeeper ledger" document.
```

## Commands

Everything works by plain chat. Mention an agent to talk to it directly.

- Paste any install line, or a coding agent's answer that contains one. Scout checks it.
- Drop a `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml` or `Pipfile` into the chat. Scout reads it through Switch's media store and checks every dependency.
- `approve <name>`: allow a risky package in this room (your name is recorded).
- `@fixer rules`: show this room's rules and approvals.
- `@fixer rule min-age 60`: packages younger than 60 days need approval here.
- `@fixer rule install-scripts on`: anything that runs a script on install needs approval here.
- `@fixer revoke <name>`: take an approval back.
- `@inspector npm:left-pad` or `@inspector pypi:requests`: read any package on demand.
- `@squat-watch list`: names this team's agents invented, and how often.
- `@squat-watch npm:some-name`: watch a name by hand.

## Why this needs Switch

Gatekeeper is not a bot with four names. It is four agents that each have their own Switch identity, owner and connection, sitting in a Switch room next to the humans. Take Switch away and it stops working:

- **The room is the product.** Switch turns a Discord channel (or a Slack channel, or any connected chat) into one room where people and agents read the same messages. Scout sees the install line because it is a member of that room, not because we wrote a Discord bot.
- **One crew, any chat.** We never touch the Discord or Slack APIs. Switch carries the messages in and out, so the same four agents work wherever the team already talks.
- **Each agent is its own teammate.** Switch gives every agent its own identity, who-can-instruct setting and presence in the room, so the team can mention `@inspector` or `@fixer` directly, and see who said what.
- **Humans stay in charge.** The approval gate works because Switch shows the human's name on every message, so Fixer can record who approved a package.
- **The crew coordinates through Switch, not behind it.** Scout hands work to its teammates with Switch's `send_targeted_message`, so the handoff is a message the whole team can read. There is no queue or shared memory between the agents: each one could run on a different machine.
- **The team's memory lives in Switch.** The rules, approvals and the list of invented names are Switch room documents ("Gatekeeper ledger", "Invented package names") that every member of the room can open, and Switch announces every change in the chat.

## How it works

Everything the crew shares goes through Switch. There is no queue, database or shared memory between the agents.

```
 chat (Discord / Slack / ...)
            │  the Switch bridge relays the channel
      Switch room ─────────────── room documents: "Gatekeeper ledger" (Fixer), "Invented package names" (Squat Watch)
            │
  Scout ── send_targeted_message ──► @inspector @squat-watch @fixer
            each teammate gets an addressed Switch event and reads its own line;
            the people in the room see the handoff as plain text
```

1. A person (or their coding agent's answer) posts an install line. Every agent's WebSocket gets the `message` event.
2. **Scout** reads the room's rules and approvals from the **Gatekeeper ledger** room document (`connect_to_room`, `load_internal_documents`), checks each package live, and posts its verdict.
3. If anything is wrong, Scout hands the case over with **one `send_targeted_message`**: "Inspector, read `npm:expres` · Squat Watch, watch `npm:number-to-words-indian` · Fixer, make this safe: `npm i …`". Switch turns it into an addressed event for each teammate.
4. **Inspector**, **Squat Watch** and **Fixer** each verify on their own (nobody trusts another agent's verdict blindly) and post in the room as themselves.
5. When a person types `approve esbuild`, Fixer writes it into the ledger with `create_room_document` / `update_room_document`. Scout sees it on the next check.
6. When a watched name gets registered, or a brand-new package imitates one the team installs, Squat Watch alerts the room and hands the new package to Inspector with another targeted message.
7. When someone new joins the room (`room_join`), Fixer welcomes them with the room's rules.

Because the agents only talk through Switch, each can run on its own machine: `python -u run_crew.py scout` on one, `python -u run_crew.py inspector` on another.

- `gatekeeper/switch.py`: a small client for the Switch agent protocol (register, WebSocket events with ping/pong, resume and reconnect, room-bound operations, targeted handoffs, room documents).
- `gatekeeper/crew.py`: the handoff format and the ledger document format.
- `gatekeeper/registry.py`: live npm and PyPI checks, and the lookalike test (Damerau-Levenshtein against the top 3,000 packages of each ecosystem).
- `gatekeeper/inspect_pkg.py`: the in-memory archive reader and the rules.
- `gatekeeper/scout.py`, `inspector.py`, `squat_watch.py`, `fixer.py`: the four agents.

## How well it works

We measured Inspector on **real malware** from Datadog's open [malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset) (packages removed from npm and PyPI after human triage) and on the **most popular real packages**. The rules were tuned on one set of samples; the numbers below come from samples that were held out until the end.

**npm:** of 200 malicious packages never seen during tuning, Inspector flagged **60.5%** (38% outright "malicious-looking"). Of 500 popular packages, it wrongly called **1 (0.2%)** malicious and asked for a human look on 0.8%.

**PyPI:** of 196 held-out malicious packages, it flagged **84%** (70% outright). Of 470 popular packages, it wrongly called 1.5% malicious and asked for a human look on 8.3%.

Full output: [`eval/RESULTS.md`](eval/RESULTS.md). Reproduce with `python -m eval.run_eval 200 500 500` (run it on a throwaway machine: the samples are real malware, read in memory only).

**What these numbers do not include.** Inspector only reads code. In real use, Scout also flags a package that is days old, has one version and almost no downloads, which describes most fresh malware. That check cannot be replayed on packages the registries have already removed, so it is not counted above. Many npm samples we missed contain no code at all beyond a manifest, and only that metadata would catch them.

## Run it

**1. A Switch server.** Follow [Host Switch for your team](https://docs.switchagents.ai/switch-rooms/deploy/self-host.md). We run Switch 0.31.0 with Docker Compose on a small cloud VM (2 vCPU, 8 GB), with its ports bound to 127.0.0.1, and reach it from a laptop through an SSH tunnel. Connect your chat in Switch Console (we use Discord; Slack works the same way), which turns a channel into a Switch room.

**2. A registration key.** In Switch Console, create a registration key **as yourself** (the owner). Agents registered with a separate registration account work, but you can't manage or address them from your own account.

**3. The crew.**

```bash
git clone https://github.com/Ankith-m1006/gatekeeper && cd gatekeeper
cp .env.example .env               # SWITCH_API=http://localhost:8000 and SWITCH_REGISTRATION_TOKEN=<your key>
docker compose up -d --build       # registers the four agents on first start and keeps them running
docker compose logs -f             # "scout connected", "inspector connected", ...
```

Without Docker: `python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && python -u run_crew.py`. Each agent can also run on its own machine: `python -u run_crew.py scout`.

**4. Let the team talk to them.** A new agent only answers its owner. In the Switch admin page, open each agent and set **Addressing policy** to **Open** (agents can't change this themselves).

**5. Invite them.** In the chat: `!invite-agent @scout`, then `@inspector`, `@squat-watch`, `@fixer`, **one per message** (a multi-line message only runs the first line). Paste an install line, or drop a `package.json` or `requirements.txt`, and watch the crew work.

**Tests:** `pip install pytest && python -m pytest -q tests` runs 33 offline tests (no network, no Switch). CI runs them on every push.

## Safety

- Inspector never installs, extracts to disk, imports or runs a package. Archives are size-capped (25 MB download, 2 MB per file, 40 MB total read) so a zip bomb cannot hurt the host.
- Gatekeeper never installs anything for you. Fixer only proposes a command, and a person approves risky packages.
- The eval reads real malware samples in memory on a disposable VM, never on a developer machine.

## Built with

[Switch](https://github.com/sandbox-quantum/switch) for the rooms and agent identities, npm and PyPI public APIs, [npm-high-impact](https://github.com/wooorm/npm-high-impact) and [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) for the popular lists, and Datadog's dataset for the eval. Built by voice with Wispr Flow for Flip the Switch by WeMakeDevs. MIT licensed.

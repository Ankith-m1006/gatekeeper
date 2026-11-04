"""Fixer: turns a bad install into a safe one, and holds the human approval gate for the room.

Fixer never installs anything itself. It rewrites the command, and when a package is risky but the
team still wants it, a person in the room has to say so (`approve <name>`). That approval is
remembered per room, and Scout shows it next time.
"""
from __future__ import annotations

import re

from .crew import CREW, Case, RoomPolicy, key
from .switch import Agent, Event

INSTALL_LINE = re.compile(r"^.*\b(npm|yarn|pnpm|bun|npx|pip3?|uv|poetry|pipenv|python3?\s+-m\s+pip)\b.*$", re.I | re.M)
APPROVE = re.compile(r"^\s*(?:@?fixer\s+)?approve\s+(?:(npm|pypi)[:\s]+)?(@?[\w./-]+)", re.I)
REVOKE = re.compile(r"revoke\s+(?:(npm|pypi)[:\s]+)?(@?[\w./-]+)", re.I)
RULE = re.compile(r"rule\s+(min-age|install-scripts)\s+(\S+)", re.I)


def rewrite(text: str, swaps: dict[str, str | None]) -> list[str]:
    """Return the install lines from `text` with bad names swapped or removed."""
    out = []
    for line in (m.group(0) for m in INSTALL_LINE.finditer(text)):
        new = line.strip().strip("`")
        for bad, good in swaps.items():
            pat = re.compile(rf"(?<![\w@/-]){re.escape(bad)}(?=$|[\s@=<>~!\[`])")
            new = pat.sub(good or "", new)
        new = re.sub(r"\s{2,}", " ", new).strip()
        if re.search(r"\b(install|add|i)\s*$", new):  # nothing left to install
            continue
        out.append(new)
    return out


class Fixer:
    def __init__(self, agent: Agent, policy: RoomPolicy):
        self.agent, self.policy = agent, policy

    async def on_case(self, case: Case) -> None:
        swaps: dict[str, str | None] = {}
        need_ok: list[str] = []
        for r in case.reports:
            if r.verdict == "ghost" or r.similar_to:
                swaps[r.name] = r.similar_to  # the real package it imitates, or drop it
            elif r.verdict in ("suspicious", "danger"):
                need_ok.append(r.name)
        lines = []
        fixed = rewrite(case.text, swaps) if swaps else []
        if swaps:
            what = ", ".join(f"`{b}` → `{g}`" if g else f"`{b}` removed" for b, g in swaps.items())
            if fixed:
                lines.append(f"🔧 **Safe version** ({what}):\n```\n" + "\n".join(fixed) + "\n```")
            else:
                lines.append(f"🔧 Nothing safe left to install here ({what}). If you need this feature, ask your coding agent for a package that exists, and Scout will check it.")
            if any(g is None for g in swaps.values()):
                lines.append("   ↳ a name with no real match usually means the coding agent invented it. Ask it which package it meant, or write those few lines yourself.")
        if need_ok:
            names = ", ".join(f"`{n}`" for n in need_ok)
            lines.append(f"✋ {names} {'is' if len(need_ok) == 1 else 'are'} not blocked, but this room asks a person to look first. Reply `approve {need_ok[0]}` to allow it here, and I'll remember.")
        if lines:
            await self.agent.send(case.room_id, "\n".join(lines))

    async def on_event(self, ev: Event) -> None:
        if ev.type != "message" or not ev.body or ev.sender.lower() in CREW:
            return
        body = ev.body.strip()
        m = APPROVE.match(body)
        if m:  # anyone in the room may approve; their name is recorded
            name = m.group(2)
            ecos = [m.group(1).lower()] if m.group(1) else ["npm", "pypi"]
            for eco in ecos:
                self.policy.approve(ev.room_id, f"{eco}:{name}", ev.sender or "someone")
            await self.agent.send(ev.room_id, f"✅ `{name}` approved for this room by {ev.sender or 'someone'}. Scout will show the approval next time; say @fixer revoke {name} to take it back.")
            return
        if not ev.addressed:
            return
        if m := REVOKE.search(body):
            name = m.group(2)
            gone = any(self.policy.revoke(ev.room_id, f"{e}:{name}") for e in ("npm", "pypi"))
            await self.agent.send(ev.room_id, f"Approval for `{name}` removed." if gone else f"`{name}` was not approved here.")
        elif m := RULE.search(body):
            rule, val = m.group(1).lower(), m.group(2).lower()
            if rule == "min-age" and val.isdigit():
                self.policy.set_rule(ev.room_id, "min_age_days", int(val))
                await self.agent.send(ev.room_id, f"Rule set: packages younger than **{val} days** need a person's approval in this room.")
            elif rule == "install-scripts" and val in ("on", "off"):
                self.policy.set_rule(ev.room_id, "block_install_scripts", val == "on")
                await self.agent.send(ev.room_id, f"Rule set: packages that run a script on install {'now need' if val == 'on' else 'no longer need'} approval in this room.")
            else:
                await self.agent.send(ev.room_id, "Rules I know: @fixer rule min-age 60, @fixer rule install-scripts on/off.")
        else:
            r = self.policy.rules(ev.room_id)
            ok = self.policy.approvals(ev.room_id)
            seen: dict[str, str] = {}
            for k, v in ok.items():
                seen.setdefault(k.split(":", 1)[1], v["by"])
            approved = ", ".join(f"`{n}` ({by})" for n, by in seen.items()) or "none yet"
            await self.agent.send(ev.room_id, (
                "**This room's rules:**\n"
                f"• packages younger than {r['min_age_days']} days need approval (say @fixer rule min-age N)\n"
                f"• install scripts need approval: {'yes' if r['block_install_scripts'] else 'no'} (say @fixer rule install-scripts on/off)\n"
                f"• approved here: {approved}\n"
                "Approve with `approve <name>`; take back with @fixer revoke <name>."
            ))

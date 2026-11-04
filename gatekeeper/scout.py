"""Scout: watches the room for new dependencies and checks each one live."""
from __future__ import annotations

import asyncio
import logging

from . import registry
from .crew import CREW, Board, Case, RoomPolicy, key
from .extract import packages_in
from .switch import Agent, Event

log = logging.getLogger(__name__)

ICON = {"ghost": "👻", "danger": "⛔", "suspicious": "⚠️", "ok": "✅"}
LINK = {"npm": "https://www.npmjs.com/package/{}", "pypi": "https://pypi.org/project/{}/"}
ORDER = ["ok", "suspicious", "danger", "ghost"]


def describe(r: registry.PackageReport, approval: dict | None = None) -> str:
    icon = "☑️" if approval and r.exists else ICON[r.verdict]
    head = f"{icon} **{r.name}** ({r.ecosystem})"
    if r.verdict == "ghost":
        line = f"{head}: **does not exist**. Nobody should install this name: if anyone registers it later, it is a trap."
        if r.similar_to:
            line += f" Did you mean `{r.similar_to}`?"
        return line
    facts = []
    if r.age_days is not None:
        facts.append(f"{r.age_days // 365}y old" if r.age_days >= 365 else f"{r.age_days} days old")
    if r.downloads is not None:
        facts.append(f"{r.downloads:,} downloads/{'week' if r.ecosystem == 'npm' else 'month'}")
    facts.append(f"{r.versions} versions")
    line = f"{head}: {', '.join(facts)}. <{LINK[r.ecosystem].format(r.name)}>"
    if r.flags:
        line += "\n   ↳ " + "; ".join(r.flags)
    if approval and r.verdict != "ok":
        line += f"\n   ↳ approved for this room by {approval['by']} ({approval['at']})"
    return line


class Scout:
    def __init__(self, agent: Agent, board: Board, policy: RoomPolicy):
        self.agent, self.board, self.policy = agent, board, policy

    async def on_event(self, ev: Event) -> None:
        if ev.type != "message" or not ev.body:
            return
        if ev.sender.lower() in CREW:  # never re-check the crew's own posts
            return
        pkgs = packages_in(ev.body)
        if not pkgs:
            if ev.addressed:
                await self.agent.send(ev.room_id, "I check every package your team or its coding agents are about to install. Paste an `npm install` or `pip install` line, or ask a coding agent for one, and I'll check it live.")
            return
        reports = await asyncio.gather(*(registry.check(e, n) for e, n in pkgs[:8]))
        rules = self.policy.rules(ev.room_id)
        for r in reports:  # room rules can make a package stricter
            if r.exists and rules.get("block_install_scripts") and r.has_install_scripts and r.verdict == "ok":
                r.flags.append("runs a script on install (this room asks for approval)")
            age, limit = r.age_days, rules.get("min_age_days", 30)
            if r.exists and age is not None and 30 <= age < limit:
                r.flags.append(f"{age} days old (this room wants {limit}+)")
        approvals = {key(r): self.policy.approval(ev.room_id, key(r)) for r in reports}
        live = [r for r in reports if not approvals[key(r)]]
        worst = max((r.verdict for r in live), key=ORDER.index, default="ok")
        title = {
            "ghost": "Stop: this install includes a package that does not exist.",
            "danger": "Stop: this looks like a typosquat of a popular package.",
            "suspicious": "Check before installing:",
            "ok": "Approved here, and the rest look fine:" if len(live) < len(reports) else "These look fine:",
        }[worst]
        body = f"**{title}**\n" + "\n".join(describe(r, approvals[key(r)]) for r in reports)
        await self.agent.send(ev.room_id, body)
        if worst != "ok":
            await self.board.open(Case(ev.room_id, ev.sender, ev.body, live))

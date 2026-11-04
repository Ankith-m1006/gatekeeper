"""Scout: watches the room for new dependencies and checks each one live."""
from __future__ import annotations

import asyncio
import logging

from . import registry
from .extract import packages_in
from .switch import Agent, Event

log = logging.getLogger(__name__)

ICON = {"ghost": "👻", "danger": "⛔", "suspicious": "⚠️", "ok": "✅"}
LINK = {"npm": "https://www.npmjs.com/package/{}", "pypi": "https://pypi.org/project/{}/"}


def describe(r: registry.PackageReport) -> str:
    head = f"{ICON[r.verdict]} **{r.name}** ({r.ecosystem})"
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
    return line


class Scout:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def on_event(self, ev: Event) -> None:
        if ev.type != "message" or not ev.body:
            return
        sender = ev.sender.lower()
        if sender in {"scout", "inspector", "squat-watch", "fixer"}:  # never re-check the crew's own posts
            return
        pkgs = packages_in(ev.body)
        if not pkgs:
            if ev.addressed:
                await self.agent.send(ev.room_id, "I check every package your team or its coding agents are about to install. Paste an `npm install` or `pip install` line, or ask a coding agent for one, and I'll check it live.")
            return
        reports = await asyncio.gather(*(registry.check(e, n) for e, n in pkgs[:8]))
        worst = max(reports, key=lambda r: ["ok", "suspicious", "danger", "ghost"].index(r.verdict))
        title = {
            "ghost": "Stop: this install includes a package that does not exist.",
            "danger": "Stop: this looks like a typosquat of a popular package.",
            "suspicious": "Check before installing:",
            "ok": "These look fine:",
        }[worst.verdict]
        body = f"**Scout** · {title}\n" + "\n".join(describe(r) for r in reports)
        await self.agent.send(ev.room_id, body)

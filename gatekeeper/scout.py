"""Scout: watches the room for new dependencies and checks each one live."""
from __future__ import annotations

import asyncio
import logging
import time

from . import registry
from .crew import CREW, DEFAULT_RULES, LEDGER, RoomPolicy, handoff, key, parse_ledger
from .extract import INSTALL_LINE
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
    def __init__(self, agent: Agent, policy: RoomPolicy):
        self.agent, self.policy = agent, policy
        self._ledger: dict[str, tuple[float, dict]] = {}

    async def room_ledger(self, room_id: str) -> dict:
        """Rules and approvals from the ledger document Fixer keeps in the Switch room."""
        hit = self._ledger.get(room_id)
        if hit and time.time() - hit[0] < 10:
            return hit[1]
        data = None
        try:
            _, content = await self.agent.read_document(room_id, LEDGER)
            data = parse_ledger(content)
        except Exception as e:  # Switch unreachable: fall back to the local copy
            log.warning("scout could not read the ledger: %s", e)
        if data is None:
            data = {"rules": self.policy.rules(room_id), "approved": self.policy.approvals(room_id)}
        self._ledger[room_id] = (time.time(), data)
        return data

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
        reports, ledger = await asyncio.gather(
            asyncio.gather(*(registry.check(e, n) for e, n in pkgs[:8])),
            self.room_ledger(ev.room_id),
        )
        rules = {**DEFAULT_RULES, **ledger.get("rules", {})}
        for r in reports:  # room rules can make a package stricter
            if r.exists and rules.get("block_install_scripts") and r.has_install_scripts and r.verdict == "ok":
                r.flags.append("runs a script on install (this room asks for approval)")
            age, limit = r.age_days, rules.get("min_age_days", 30)
            if r.exists and age is not None and 30 <= age < limit:
                r.flags.append(f"{age} days old (this room wants {limit}+)")
        approvals = {key(r): ledger.get("approved", {}).get(key(r)) for r in reports}
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
        if worst == "ok":
            return
        # Hand the case to the crew through Switch, as one addressed message the team can read.
        inspect = [key(r) for r in live if r.exists and r.verdict in ("danger", "suspicious")][:4]
        watch = [key(r) for r in live if r.verdict == "ghost"]
        install = "\n".join(m.group(0).strip().strip("`") for m in INSTALL_LINE.finditer(ev.body))
        names, body = handoff(ev.sender or "someone", inspect, watch, install)
        await self.agent.hand_off(ev.room_id, names, body)

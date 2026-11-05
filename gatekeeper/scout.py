"""Scout: watches the room for new dependencies and checks each one live."""
from __future__ import annotations

import asyncio
import logging
import time

from . import registry
from .crew import CREW, DEFAULT_RULES, LEDGER, RoomPolicy, handoff, key, parse_ledger
from .extract import INSTALL_LINE, is_dep_file, packages_in, packages_in_file, install_commands
from .switch import Agent, Event

log = logging.getLogger(__name__)

ICON = {"ghost": "👻", "danger": "⛔", "suspicious": "⚠️", "ok": "✅"}
LINK = {"npm": "https://www.npmjs.com/package/{}", "pypi": "https://pypi.org/project/{}/"}
ORDER = ["ok", "suspicious", "danger", "ghost"]
NL = "\n"


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
        line += NL + "   ↳ " + "; ".join(r.flags)
    if approval and r.verdict != "ok":
        line += NL + f"   ↳ approved for this room by {approval['by']} ({approval['at']})"
    return line


def install_lines(pkgs: list[tuple[str, str]]) -> str:
    """Describe a list of packages as install lines (one per ecosystem), so Fixer can rewrite them."""
    lines = []
    for eco, cmd in (("npm", "npm i "), ("pypi", "pip install ")):
        names = [n for e, n in pkgs if e == eco]
        if names:
            lines.append(cmd + " ".join(names))
    return NL.join(lines)


class Scout:
    def __init__(self, agent: Agent, policy: RoomPolicy):
        self.agent, self.policy = agent, policy
        self._ledger: dict[str, tuple[float, dict]] = {}
        self._agents: dict[str, tuple[float, set[str]]] = {}
        self._recent: dict[tuple[str, str, tuple], float] = {}

    async def room_agents(self, room_id: str) -> set[str]:
        """Names of the agents in the room, so a coding agent's request gets an addressed answer it wakes up to."""
        hit = self._agents.get(room_id)
        if hit and time.time() - hit[0] < 60:
            return hit[1]
        names: set[str] = set()
        try:
            d = await self.agent.op("get_room_detail", _bind=False, room_id=room_id)
            names = {str(n).lower() for n in (d or {}).get("agent_names") or []}
        except Exception as e:
            log.warning("scout could not list room agents: %s", e)
        self._agents[room_id] = (time.time(), names)
        return names

    def repeat(self, ev: Event, pkgs: list[tuple[str, str]]) -> bool:
        """True when the same sender asked about the same packages in the last 5 minutes (a coding agent restating its plan)."""
        now = time.time()
        self._recent = {k: t for k, t in self._recent.items() if now - t < 300}
        k = (ev.room_id, ev.sender.lower(), tuple(sorted(pkgs)))
        if k in self._recent:
            return True
        self._recent[k] = now
        return False

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
            log.info("scout: no ledger document in room %s yet, using the local copy", room_id[:8])
            data = {"rules": self.policy.rules(room_id), "approved": self.policy.approvals(room_id)}
        else:
            log.info("scout: read the ledger from the Switch room document (%d approvals)", len(data.get("approved", {})))
        self._ledger[room_id] = (time.time(), data)
        return data

    async def on_event(self, ev: Event) -> None:
        if ev.type != "message":
            return
        if ev.sender.lower() in CREW:  # never re-check the crew's own posts
            return
        files = [a for a in (ev.payload.get("attachments") or []) if is_dep_file(str(a.get("filename", "")))]
        if files:
            await self.check_files(ev, files)
        if not ev.body:
            return
        pkgs = packages_in(ev.body)
        if not pkgs:
            if ev.addressed and not files:
                await self.agent.send(ev.room_id, "I check every package your team or its coding agents are about to install. Paste an `npm install` or `pip install` line, drop a `package.json` or `requirements.txt`, or ask a coding agent for one, and I'll check it live.")
            return
        if self.repeat(ev, pkgs[:8]):
            log.info("scout: %s repeated the same install within 5 min, not re-checking", ev.sender)
            return
        install = install_commands(ev.body) or install_lines(pkgs[:8])
        await self.check(ev, pkgs[:8], install, source=None)

    async def check_files(self, ev: Event, files: list[dict]) -> None:
        """A dependency file dropped into the chat: read it through Switch's media store and check what it declares."""
        for a in files[:3]:
            name = str(a.get("filename"))
            try:
                text = (await self.agent.download(ev.room_id, str(a.get("mxc")))).decode("utf-8", "replace")
            except Exception as e:
                await self.agent.send(ev.room_id, f"I couldn't read `{name}` ({e}).")
                continue
            pkgs = packages_in_file(name, text)
            if not pkgs:
                await self.agent.send(ev.room_id, f"`{name}` doesn't declare any packages I can check.")
                continue
            await self.check(ev, pkgs[:25], "", source=(name, len(pkgs)))

    async def check(self, ev: Event, pkgs: list[tuple[str, str]], install: str, source: tuple[str, int] | None) -> None:
        reports, ledger = await asyncio.gather(
            asyncio.gather(*(registry.check(e, n) for e, n in pkgs)),
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
        if source:  # a whole file: list only what needs attention
            fname, total = source
            shown = [r for r in reports if r.verdict != "ok" or approvals[key(r)]]
            fine = len(reports) - len(shown)
            more = f" (first {len(reports)} of {total})" if total > len(reports) else ""
            body = f"📄 **{fname}**: checked {len(reports)} dependencies{more}. **{title}**" + NL + NL.join(describe(r, approvals[key(r)]) for r in shown)
            if fine:
                body += NL + f"✅ {fine} other{'s' if fine != 1 else ''} look fine."
        else:
            body = f"**{title}**" + NL + NL.join(describe(r, approvals[key(r)]) for r in reports)
        asker = ev.sender.lower()
        if asker and asker not in CREW and asker in await self.room_agents(ev.room_id):
            # a coding agent asked: address the verdict to it, so its session wakes up and acts on it
            await self.agent.hand_off(ev.room_id, [ev.sender], body)
        else:
            await self.agent.send(ev.room_id, body)
        if worst == "ok":
            return
        # Hand the case to the crew through Switch, as one addressed message the team can read.
        inspect = [key(r) for r in live if r.exists and r.verdict in ("danger", "suspicious")][:4]
        watch = [key(r) for r in live if r.verdict == "ghost"]
        if source:  # from a file, Fixer only needs the packages with problems
            install = install_lines([(r.ecosystem, r.name) for r in live if r.verdict != "ok"])
        names, body = handoff(ev.sender or "someone", inspect, watch, install)
        await self.agent.hand_off(ev.room_id, names, body)

"""Inspector: reads the code of any risky package Scout finds, without ever running it."""
from __future__ import annotations

import asyncio
import re

from .crew import CREW, Case
from .inspect_pkg import Inspection, inspect
from .switch import Agent, Event

ICON = {"malicious-looking": "🚨", "risky": "🟠", "clean": "🟢", "unknown": "❔"}
SAY = {
    "malicious-looking": "this code does things a normal package should not. Do not install.",
    "risky": "nothing clearly malicious, but some of this deserves a look before you install.",
    "clean": "I read the code and found nothing that steals, downloads or hides anything.",
    "unknown": "I could not read this package",
}
ASK = re.compile(r"(?:inspect\s+)?(npm|pypi|pip)[:\s]+(@?[\w./-]+)", re.I)


def render(res: Inspection) -> str:
    v = res.verdict
    head = f"{ICON[v]} **{res.name}**"
    if res.version:
        head += f"@{res.version}"
    if v == "unknown":
        return f"{head}: {SAY[v]} ({res.error})."
    out = f"{head}: read {res.files_read} files, ran none. {SAY[v]}"
    for k, cmd in res.install_scripts.items():
        out += f"\n   ↳ runs on install ({k}): `{cmd[:90]}`"
    for f in res.findings[:5]:
        where = f"{f.file}:{f.line}" + (", runs on install/import" if f.autorun else "")
        out += f"\n   ↳ {f.label} ({where})"
    return out


class Inspector:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def on_case(self, case: Case) -> None:
        # Only packages that exist can be read; ghosts belong to Squat Watch.
        targets = [r for r in case.reports if r.exists and r.verdict in ("danger", "suspicious")]
        if not targets:
            return
        results = await asyncio.gather(*(inspect(r.ecosystem, r.name) for r in targets[:4]))
        await self.agent.send(case.room_id, "**I opened the package and read the code:**\n" + "\n".join(render(x) for x in results))

    async def on_event(self, ev: Event) -> None:
        """`@inspector npm:left-pad` or `@inspector pypi requests` inspects on demand."""
        if ev.type != "message" or not ev.addressed or ev.sender.lower() in CREW:
            return
        m = ASK.search(ev.body)
        if not m:
            await self.agent.send(ev.room_id, "Tell me what to read, like @inspector npm:left-pad or @inspector pypi:requests. I download the archive into memory and read it; I never install or run it.")
            return
        eco = "npm" if m.group(1).lower() == "npm" else "pypi"
        res = await inspect(eco, m.group(2))
        await self.agent.send(ev.room_id, render(res))

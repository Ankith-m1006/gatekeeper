"""Inspector: reads the code of any risky package Scout finds, without ever running it."""
from __future__ import annotations

import asyncio
import re

from .crew import CREW, my_part, tokens
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

    async def read_and_report(self, room_id: str, targets: list[tuple[str, str]], why: str = "") -> None:
        results = await asyncio.gather(*(inspect(e, n) for e, n in targets[:4]))
        head = "**I opened the package and read the code" + (f" ({why})" if why else "") + ":**\n"
        await self.agent.send(room_id, head + "\n".join(render(x) for x in results))

    async def on_event(self, ev: Event) -> None:
        """Handoffs from Scout or Squat Watch, or `@inspector npm:left-pad` from a person."""
        if ev.type != "message" or not ev.addressed:
            return
        sender = ev.sender.lower()
        if sender in ("scout", "squat-watch"):  # a teammate handed work over through Switch
            part = my_part(ev.body, "inspector")
            if part and (targets := tokens(part)):
                await self.read_and_report(ev.room_id, targets, "just registered" if sender == "squat-watch" else "")
            return
        if sender in CREW:
            return
        m = ASK.search(ev.body)
        if not m:
            await self.agent.send(ev.room_id, "Tell me what to read, like @inspector npm:left-pad or @inspector pypi:requests. I download the archive into memory and read it; I never install or run it.")
            return
        eco = "npm" if m.group(1).lower() == "npm" else "pypi"
        res = await inspect(eco, m.group(2))
        await self.agent.send(ev.room_id, render(res))

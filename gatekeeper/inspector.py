"""Inspector: reads the code of any risky package Scout finds, without ever running it."""
from __future__ import annotations

import asyncio
import re

from .agent_guard import agent_instructions, hidden_text, is_code_file, is_instruction_file
from .crew import CREW, my_part, tokens
from .inspect_pkg import Inspection, inspect, read_script, scan_text
from .switch import Agent, Event

ICON = {"malicious-looking": "🚨", "risky": "🟠", "clean": "🟢", "unknown": "❔"}
SAY = {
    "malicious-looking": "this code does things a normal package should not. Do not install.",
    "risky": "nothing clearly malicious, but some of this deserves a look before you install.",
    "clean": "I read the code and found nothing that steals, downloads or hides anything.",
    "unknown": "I could not read this package",
}
ASK = re.compile(r"(?:\binspect\s+(npm|pypi|pip)\s+|\b(npm|pypi|pip):)(@?[\w./-]+)", re.I)
URL = re.compile(r"https?://[^\s`'\"<>|)]+")


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

    async def report_script(self, room_id: str, url: str) -> None:
        """Read an install script from its link, as text, without running it."""
        res = await read_script(url)
        if res.error:
            await self.agent.send(room_id, f"❔ I couldn't read the script at <{url}> ({res.error}). Don't run what nobody can read.")
            return
        v = res.verdict
        say = {"malicious-looking": "this script does things an installer should not. Do not run it.",
               "risky": "nothing clearly malicious, but read these lines before anyone runs it.",
               "clean": "it installs and nothing more: no keys read, no data sent out, nothing hidden."}[v]
        out = [f"{ICON[v]} **Install script** <{url}>: I downloaded it as text and ran nothing. {say}"]
        for f in sorted(res.findings, key=lambda f: -f.severity)[:5]:
            if f.severity >= 2:
                out.append(f"   ↳ {f.label} (line {f.line})")
        await self.agent.send(room_id, "\n".join(out))

    async def read_file(self, ev: Event, a: dict) -> None:
        """An agent rules file, MCP config or code file dropped into the room: read what the agent would read."""
        name = str(a.get("filename"))
        try:
            text = (await self.agent.download(ev.room_id, str(a.get("mxc")))).decode("utf-8", "replace")
        except Exception as e:
            await self.agent.send(ev.room_id, f"I couldn't open `{name}` ({e}).")
            return
        h = hidden_text(text)
        hits = agent_instructions(text)
        code = scan_text(name, text) if is_code_file(name) else []
        if not (h.found or hits or code):
            if is_instruction_file(name):
                await self.agent.send(ev.room_id, f"🟢 **{name}**: I read every character, including the invisible ones. Nothing hidden, and nothing that tells an agent to work against you.")
            return
        out = [f"🚨 **{name}**: this file tells an AI agent something you can't see or wouldn't want." if (h.tags or hits) else f"🟠 **{name}**: worth a look before anyone runs it."]
        if h.tags:
            out.append(f"   ↳ **{h.tags} invisible characters** on line {', '.join(map(str, h.lines[:4]))}. People and chat apps don't show them; coding agents read them. Decoded, they say:")
            out += [f"   > {d[:220]}" for d in h.decoded[:3]]
        elif h.found:
            out.append(f"   ↳ invisible characters on line {', '.join(map(str, h.lines[:4]))} ({h.zero_width} zero-width, {h.bidi} direction-changing)")
        for label, line, snip in hits[:4]:
            out.append(f"   ↳ {label} (line {line}): \"{snip[:110]}\"")
        for f in code[:3]:
            out.append(f"   ↳ {f.label} (line {f.line})")
        await self.agent.send(ev.room_id, "\n".join(out))
        if h.found or hits:
            who = ev.sender or "someone"
            await self.agent.hand_off(ev.room_id, ["fixer"], f"Over to the crew ({who}'s file):\n• Fixer, clean `{name}` {a.get('mxc')}")

    async def read_pasted(self, ev: Event) -> None:
        """Text pasted into the room that carries invisible characters (copied from a web page, an issue, a prompt)."""
        h = hidden_text(ev.body)
        if not h.tags:
            return
        out = [f"🚨 That message from {ev.sender or 'someone'} carries **{h.tags} invisible characters**. You can't see them; an AI agent reading this room can. Decoded:"]
        out += [f"   > {d[:220]}" for d in h.decoded[:3]]
        out.append("   ↳ If you copied it from somewhere, don't feed it to a coding agent. Retype it, or ask @fixer for a clean copy.")
        await self.agent.send(ev.room_id, "\n".join(out))

    async def on_event(self, ev: Event) -> None:
        """Handoffs from Scout or Squat Watch, `@inspector npm:left-pad` from a person, and files or text an agent would read."""
        if ev.type != "message":
            return
        sender = ev.sender.lower()
        if sender not in CREW:
            files = [a for a in (ev.payload.get("attachments") or []) if is_instruction_file(str(a.get("filename", ""))) or is_code_file(str(a.get("filename", "")))]
            for a in files[:3]:
                await self.read_file(ev, a)
            if ev.body:
                await self.read_pasted(ev)
        if not ev.addressed:
            return
        if sender in ("scout", "squat-watch"):  # a teammate handed work over through Switch
            part = my_part(ev.body, "inspector")
            if part and "read the script" in part and (u := URL.search(part)):
                await self.report_script(ev.room_id, u.group(0))
                return
            if part and (targets := tokens(part)):
                why = "just registered" if sender == "squat-watch" else ("an MCP server, tool descriptions included" if "MCP server" in part else "")
                await self.read_and_report(ev.room_id, targets, why)
            return
        if sender in CREW:
            return
        if re.search(r"\bscript\b|install\.sh|\.sh\b", ev.body, re.I) and (u := URL.search(ev.body)):
            await self.report_script(ev.room_id, u.group(0))
            return
        m = ASK.search(ev.body)
        if not m:
            await self.agent.send(ev.room_id, "Tell me what to read, like @inspector npm:left-pad or @inspector pypi:requests. I download the archive into memory and read it; I never install or run it.")
            return
        eco = "npm" if (m.group(1) or m.group(2)).lower() == "npm" else "pypi"
        res = await inspect(eco, m.group(3))
        await self.agent.send(ev.room_id, render(res))

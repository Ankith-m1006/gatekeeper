"""Fixer: turns a bad install into a safe one, and holds the human approval gate for the room.

Fixer never installs anything itself. It rewrites the command, and when a package is risky but the
team still wants it, a person in the room has to say so (`approve <name>`). Rules and approvals live
in a Switch room document, the "Gatekeeper ledger", which Fixer keeps and Scout reads.
"""
from __future__ import annotations

import asyncio
import logging
import re

from . import registry
from .agent_guard import clean_lines
from .crew import CREW, LEDGER, RoomPolicy, asker_of, ledger_text, my_part
from .extract import INSTALL_LINE, packages_in
from .switch import Agent, Event

log = logging.getLogger(__name__)
APPROVE = re.compile(r"^\s*(?:@?fixer\s+)?approve\s+(?:(npm|pypi)[:\s]+)?(@?[\w./-]+)(?:(?:@|==)v?(\d[\w.+-]*))?", re.I)
REVOKE = re.compile(r"revoke\s+(?:(npm|pypi)[:\s]+)?(@?[\w./-]+)", re.I)
RULE = re.compile(r"rule\s+(min-age|install-scripts)\s+(\S+)", re.I)
CLEAN = re.compile(r"Fixer, clean `([^`]+)` ([a-z][\w+.-]*://\S+)")
LOG = re.compile(r"Fixer, log: (.+)")


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

    async def sync_ledger(self, room_id: str) -> None:
        """Write this room's rules and approvals into the Switch room document."""
        room = self.policy._room(room_id)
        text = ledger_text({k: v for k, v in room.items() if k in ("rules", "approved", "incidents")})
        if room.get("doc_id") and room.get("doc_text") == text:
            return  # nothing changed; don't post an "updated" notice into the room
        try:
            doc_id = await self.agent.write_document(
                room_id, room.get("doc_id"), LEDGER,
                "Rules and human approvals for packages in this room, kept by Fixer.", text)
            if doc_id:
                room["doc_id"], room["doc_text"] = doc_id, text
                self.policy.save()
        except Exception as e:
            log.warning("fixer could not write the ledger: %s", e)

    async def clean_file(self, ev: Event, name: str, mxc: str) -> None:
        """Post the file without its invisible characters or the lines that turn the agent against its user."""
        try:
            text = (await self.agent.download(ev.room_id, mxc)).decode("utf-8", "replace")
        except Exception as e:
            await self.agent.send(ev.room_id, f"I couldn't open `{name}` to clean it ({e}).")
            return
        cleaned, dropped = clean_lines(text)
        self.policy.log_incident(ev.room_id, f"hidden or hostile agent instructions in {name}, {dropped} line(s) removed", asker_of(ev.body))
        await self.sync_ledger(ev.room_id)
        body = cleaned if len(cleaned) <= 1500 else cleaned[:1500] + "\n…"
        await self.agent.send(ev.room_id, (
            f"🔧 **Clean `{name}`**: invisible characters stripped, {dropped} line{'s' if dropped != 1 else ''} that told the agent to work against you removed. "
            f"Use this copy; logged in the \"{LEDGER}\".\n```\n{body}\n```"))

    async def on_handoff(self, ev: Event) -> None:
        part = my_part(ev.body, "fixer")
        if not part:
            return
        if m := CLEAN.search(part):
            await self.clean_file(ev, m.group(1), m.group(2))
            return
        if m := LOG.search(part):
            self.policy.log_incident(ev.room_id, m.group(1).strip(), asker_of(ev.body))
            await self.sync_ledger(ev.room_id)
            return
        pkgs = packages_in(part)
        reports = await asyncio.gather(*(registry.check(e, n) for e, n in pkgs[:8]))
        approved = self.policy.approvals(ev.room_id)
        swaps: dict[str, str | None] = {}
        need_ok: list[str] = []
        for r in reports:
            if approved.get(f"{r.ecosystem}:{r.name}"):
                continue
            if r.verdict == "ghost" or r.similar_to:
                swaps[r.name] = r.similar_to  # the real package it imitates, or drop it
            elif r.verdict in ("suspicious", "danger"):
                need_ok.append(r.name)
        lines = []
        if swaps:
            fixed = rewrite(part, swaps)
            what = ", ".join(f"`{b}` → `{g}`" if g else f"`{b}` removed" for b, g in swaps.items())
            if fixed:
                lines.append(f"🔧 **Safe version** ({what}):\n```\n" + "\n".join(fixed) + "\n```")
            else:
                lines.append(f"🔧 Nothing safe left to install here ({what}). If you need this feature, ask your coding agent for a package that exists, and Scout will check it.")
            if any(g is None for g in swaps.values()):
                lines.append("   ↳ a name with no real match usually means the coding agent invented it. Ask it which package it meant, or write those few lines yourself.")
        if need_ok:
            names = ", ".join(f"`{n}`" for n in need_ok)
            lines.append(f"✋ {names} {'is' if len(need_ok) == 1 else 'are'} not blocked, but this room asks a person to look first. {asker_of(ev.body)}, or anyone here: reply `approve {need_ok[0]}` to allow it, and I'll write it in the ledger.")
        if lines:
            await self.agent.send(ev.room_id, "\n".join(lines))

    async def welcome(self, ev: Event) -> None:
        who = ev.payload.get("member_name") or ""
        if not who or who.lower() in CREW or who.lower() in ("gatekeeper", "switch"):
            return
        r = self.policy.rules(ev.room_id)
        await self.agent.send(ev.room_id, (
            f"👋 Welcome, {who}. This room has a security crew for people and their coding agents. Scout checks every package and MCP server before it's added, "
            f"and speaks up on leaked keys and dangerous commands. Inspector reads risky code, MCP tool descriptions and agent rules files "
            f"(including text you can't see). Squat Watch tracks names agents invent, and I keep the rules and hand you safe versions. "
            f"Here, packages younger than {r['min_age_days']} days need a person's approval. The full rules are in the room document \"{LEDGER}\"."))

    async def on_event(self, ev: Event) -> None:
        if ev.type == "room_join":
            await self.welcome(ev)
            return
        if ev.type != "message" or not ev.body:
            return
        if ev.sender.lower() in ("scout", "inspector") and ev.addressed:
            await self.on_handoff(ev)
            return
        if ev.sender.lower() in CREW:
            return
        body = ev.body.strip()
        m = APPROVE.match(body)
        if m:  # anyone in the room may approve; their name is recorded
            name = m.group(2)
            ecos = [m.group(1).lower()] if m.group(1) else ["npm", "pypi"]
            for eco in ecos:
                version = m.group(3)  # `approve foo@1.2.0` approves exactly that version
                if not version:
                    try:
                        rep = await registry.check(eco, name)
                        version = rep.latest if rep.exists else None
                    except Exception:
                        version = None
                self.policy.approve(ev.room_id, f"{eco}:{name}", ev.sender or "someone", version)
            await self.sync_ledger(ev.room_id)
            await self.agent.send(ev.room_id, f"✅ `{name}` approved for this room by {ev.sender or 'someone'} (this version only: a new release gets checked again), written in the \"{LEDGER}\" document. Scout will show it next time; say @fixer revoke {name} to take it back.")
            return
        if not ev.addressed:
            return
        if m := REVOKE.search(body):
            name = m.group(2)
            gone = any([self.policy.revoke(ev.room_id, f"{e}:{name}") for e in ("npm", "pypi")])
            await self.sync_ledger(ev.room_id)
            await self.agent.send(ev.room_id, f"Approval for `{name}` removed from the ledger." if gone else f"`{name}` was not approved here.")
        elif m := RULE.search(body):
            rule, val = m.group(1).lower(), m.group(2).lower()
            if rule == "min-age" and val.isdigit():
                self.policy.set_rule(ev.room_id, "min_age_days", int(val))
                await self.sync_ledger(ev.room_id)
                await self.agent.send(ev.room_id, f"Rule set: packages younger than **{val} days** need a person's approval in this room. Written in the ledger.")
            elif rule == "install-scripts" and val in ("on", "off"):
                self.policy.set_rule(ev.room_id, "block_install_scripts", val == "on")
                await self.sync_ledger(ev.room_id)
                await self.agent.send(ev.room_id, f"Rule set: packages that run a script on install {'now need' if val == 'on' else 'no longer need'} approval in this room. Written in the ledger.")
            else:
                await self.agent.send(ev.room_id, "Rules I know: @fixer rule min-age 60, @fixer rule install-scripts on/off.")
        else:
            r = self.policy.rules(ev.room_id)
            seen: dict[str, str] = {}
            for k, v in self.policy.approvals(ev.room_id).items():
                seen.setdefault(k.split(":", 1)[1], v["by"])
            approved = ", ".join(f"`{n}` ({by})" for n, by in seen.items()) or "none yet"
            await self.agent.send(ev.room_id, (
                "**This room's rules** (also in the room document \"" + LEDGER + "\"):\n"
                f"• packages younger than {r['min_age_days']} days need approval (say @fixer rule min-age N)\n"
                f"• install scripts need approval: {'yes' if r['block_install_scripts'] else 'no'} (say @fixer rule install-scripts on/off)\n"
                f"• approved here: {approved}\n"
                "Approve with `approve <name>`; take back with @fixer revoke <name>."
            ))

    async def publish_on_start(self) -> None:
        """Once connected, make sure every known room has an up-to-date ledger document."""
        while not self.agent.connected:
            await asyncio.sleep(1)
        rooms = [r["room_id"] for r in (await self.agent.op("list_rooms", _bind=False) or []) if not r.get("archived")]
        for room_id in rooms:
            await self.sync_ledger(room_id)

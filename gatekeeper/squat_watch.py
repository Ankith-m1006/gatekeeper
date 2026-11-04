"""Squat Watch: remembers every package name the team's agents invented, and watches the registries.

A name that does not exist today is the perfect trap tomorrow: attackers register the names coding
agents hallucinate ("slopsquatting"). Squat Watch keeps this team's private list of those names and
checks npm and PyPI every few minutes. The moment one gets registered, it raises the alarm and asks
Inspector to read what was published.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path

import httpx

from .crew import CREW, STATE, asker_of, my_part, tokens
from .extract import packages_in
from .registry import UA, imitates
from .switch import Agent, Event

log = logging.getLogger(__name__)
POLL_SECONDS = 300
FRESH_SECONDS = 120  # how often to read the npm and PyPI new-package feeds
ASK = re.compile(r"(npm|pypi|pip)[:\s]+(@?[\w./-]+)", re.I)


class SquatWatch:
    def __init__(self, agent: Agent):
        self.agent = agent
        self.file: Path = STATE / "watchlist.json"
        data = json.loads(self.file.read_text()) if self.file.exists() else {}
        self.docs: dict = data.pop("_docs", {})  # room id -> Switch document id
        self.doc_texts: dict = data.pop("_doc_texts", {})  # room id -> last content we published
        self.team: dict = data.pop("_team", {})  # room id -> real packages this team installs ("eco:name")
        self.feed: dict = data.pop("_feed", {"npm_seq": None, "pypi_seen": [], "alerted": []})
        self.items: dict = data

    def save(self) -> None:
        STATE.mkdir(exist_ok=True)
        self.file.write_text(json.dumps({**self.items, "_docs": self.docs, "_doc_texts": self.doc_texts,
                                         "_team": self.team, "_feed": self.feed}, indent=1))

    def add(self, eco: str, name: str, room_id: str, by: str) -> tuple[dict, bool]:
        k = f"{eco}:{name}"
        new = k not in self.items
        it = self.items.setdefault(k, {"eco": eco, "name": name, "rooms": [], "seen": 0, "first": time.strftime("%d %b %H:%M"), "by": by, "registered": None})
        it["seen"] += 1
        if room_id not in it["rooms"]:
            it["rooms"].append(room_id)
        self.save()
        return it, new

    DOC = "Invented package names"

    def doc_text(self, room_id: str) -> str:
        mine = sorted((i for i in self.items.values() if room_id in i["rooms"]), key=lambda i: -i["seen"])
        lines = ["# Invented package names",
                 "Package names this team's coding agents asked for that did not exist. Squat Watch checks npm and PyPI "
                 f"every {POLL_SECONDS // 60} minutes; if one gets registered, treat it as a trap.", ""]
        for i in mine:
            state = f"REGISTERED {i['registered']} - do not install" if i["registered"] else "still unregistered"
            lines.append(f"- {i['name']} ({i['eco']}): asked for {i['seen']}x, first {i['first']}, {state}")
        if not mine:
            lines.append("- none yet")
        team = sorted(self.team.get(room_id, []))
        lines += ["", "## Lookalikes watched for",
                  "Brand-new npm and PyPI packages one typo away from these real packages this team installs get flagged in the room:", ""]
        lines += [f"- {k.split(':', 1)[1]} ({k.split(':', 1)[0]})" for k in team] or ["- none learned yet"]
        return "\n".join(lines)

    async def sync_doc(self, room_id: str) -> None:
        docs = self.docs
        text = self.doc_text(room_id)
        if docs.get(room_id) and self.doc_texts.get(room_id) == text:
            return  # nothing changed; don't post an "updated" notice into the room
        try:
            doc_id = await self.agent.write_document(room_id, docs.get(room_id), self.DOC,
                                                     "Names our agents invented, watched by Squat Watch.", text)
            if doc_id:
                docs[room_id], self.doc_texts[room_id] = doc_id, text
                self.save()
        except Exception as e:
            log.warning("squat watch could not write its document: %s", e)

    async def on_handoff(self, ev: Event) -> None:
        part = my_part(ev.body, "squat-watch")
        if not part:
            return
        lines = []
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            for eco, name in tokens(part):
                if await self.exists(c, eco, name) is not False:  # check for ourselves; only true ghosts go on the list
                    continue
                it, new = self.add(eco, name, ev.room_id, asker_of(ev.body))
                if new:
                    lines.append(f"👀 **{name}** ({eco}) is on this team's watchlist now. If anyone registers it, I'll alert here within {POLL_SECONDS // 60} minutes.")
                else:
                    lines.append(f"👀 **{name}** again: asked for **{it['seen']} times** since {it['first']}. Something keeps inventing this name, so it is exactly the kind an attacker would grab.")
        if not lines:
            return
        watching = sum(1 for k, i in self.items.items() if not i["registered"])
        await self.agent.send(ev.room_id, "\n".join(lines) + f"\n   ↳ watching {watching} invented name{'s' if watching != 1 else ''} for this team, listed in the room document \"{self.DOC}\".")
        await self.sync_doc(ev.room_id)

    async def exists(self, c: httpx.AsyncClient, eco: str, name: str) -> bool | None:
        url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}" if eco == "npm" else f"https://pypi.org/pypi/{name}/json"
        try:
            r = await c.get(url, headers=UA)
        except httpx.HTTPError:
            return None
        return True if r.status_code == 200 else False if r.status_code == 404 else None

    async def poll_once(self) -> None:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            for k, it in list(self.items.items()):
                if it["registered"]:
                    continue
                if await self.exists(c, it["eco"], it["name"]) is True:
                    it["registered"] = time.strftime("%d %b %H:%M")
                    self.save()
                    for room in it["rooms"]:
                        await self.agent.send(room, f"🚨 **{it['name']}** ({it['eco']}) was just registered. Your team's agents invented this name {it['seen']} time{'s' if it['seen'] != 1 else ''}; someone has now claimed it. Do not install it.")
                        await self.agent.hand_off(room, ["inspector"], f"Over to the crew (Squat Watch's alert):\n• Inspector, read `{it['eco']}:{it['name']}`")
                        await self.sync_doc(room)

    # ---------- brand-new lookalikes of what the team really uses ----------
    async def learn(self, ev: Event) -> None:
        """Remember the real packages people in this room install, so we know what to protect."""
        pkgs = packages_in(ev.body)[:8]
        if not pkgs:
            return
        mine = self.team.setdefault(ev.room_id, [])
        added = False
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            for eco, name in pkgs:
                k = f"{eco}:{name}"
                if k not in mine and await self.exists(c, eco, name) is True:
                    mine.append(k)
                    added = True
        if added:
            self.save()
            await self.sync_doc(ev.room_id)

    def _matches(self, eco: str, new: str) -> list[tuple[str, str]]:
        """(room, real package) pairs that a newly published name imitates."""
        out = []
        for room, deps in self.team.items():
            for k in deps:
                e, real = k.split(":", 1)
                if e == eco and imitates(new, real):
                    out.append((room, real))
        return out

    async def _alert(self, eco: str, new: str) -> None:
        hits = self._matches(eco, new)
        key = f"{eco}:{new}"
        if not hits or key in self.feed["alerted"]:
            return
        self.feed["alerted"] = (self.feed["alerted"] + [key])[-500:]
        self.save()
        for room, real in hits:
            await self.agent.send(room, (
                f"🆕 Someone just published **{new}** on {eco}, one typo away from **{real}**, which this team installs. "
                "Nobody here asked for it. If it ever shows up in an install line or a lockfile, treat it as a trap."))
            await self.agent.hand_off(room, ["inspector"], f"Over to the crew (Squat Watch's alert):\n• Inspector, read `{eco}:{new}`")

    async def fresh_once(self) -> None:
        if not any(self.team.values()):
            return
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=UA) as c:
            # npm: the public change feed. Revision "1-" means a package published for the first time.
            try:
                if self.feed["npm_seq"] is None:
                    r = await c.get("https://replicate.npmjs.com/registry/_changes", params={"descending": "true", "limit": 1})
                    self.feed["npm_seq"] = r.json().get("last_seq")
                else:
                    r = await c.get("https://replicate.npmjs.com/registry/_changes", params={"since": self.feed["npm_seq"], "limit": 5000})
                    d = r.json()
                    for row in d.get("results", []):
                        rev = (row.get("changes") or [{}])[0].get("rev", "")
                        if rev.startswith("1-"):
                            await self._alert("npm", row.get("id", ""))
                    self.feed["npm_seq"] = d.get("last_seq", self.feed["npm_seq"])
            except (httpx.HTTPError, ValueError) as e:
                log.warning("npm feed: %s", e)
            # PyPI: the newest-packages RSS.
            try:
                r = await c.get("https://pypi.org/rss/packages.xml")
                names = re.findall(r"<title>(\S+) added to PyPI</title>", r.text)
                seen = set(self.feed["pypi_seen"])
                for name in names:
                    if name not in seen:
                        await self._alert("pypi", name)
                self.feed["pypi_seen"] = (self.feed["pypi_seen"] + [n for n in names if n not in seen])[-400:]
            except httpx.HTTPError as e:
                log.warning("pypi feed: %s", e)
        self.save()

    async def fresh_forever(self) -> None:
        while True:
            try:
                await self.fresh_once()
            except Exception:
                log.exception("new-package feed poll failed")
            await asyncio.sleep(FRESH_SECONDS)

    async def watch_forever(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception:
                log.exception("squat watch poll failed")
            await asyncio.sleep(POLL_SECONDS)

    async def on_event(self, ev: Event) -> None:
        if ev.type != "message" or not ev.body:
            return
        if not ev.addressed:
            if ev.sender.lower() not in CREW:
                await self.learn(ev)
            return
        if ev.sender.lower() == "scout":
            await self.on_handoff(ev)
            return
        if ev.sender.lower() in CREW:
            return
        body = ev.body.lower()
        m = ASK.search(ev.body)
        if m and "unwatch" in body:
            k = f"{'npm' if m.group(1).lower() == 'npm' else 'pypi'}:{m.group(2)}"
            gone = self.items.pop(k, None)
            self.save()
            await self.agent.send(ev.room_id, f"Stopped watching `{k}`." if gone else f"`{k}` was not on the list.")
        elif m:
            it, _ = self.add("npm" if m.group(1).lower() == "npm" else "pypi", m.group(2), ev.room_id, ev.sender)
            await self.agent.send(ev.room_id, f"Watching **{it['name']}** ({it['eco']}). I check every {POLL_SECONDS // 60} minutes.")
        else:
            mine = [i for i in self.items.values() if ev.room_id in i["rooms"]]
            if not mine:
                await self.agent.send(ev.room_id, "No invented names caught in this room yet. Add one with @squat-watch npm:some-name.")
                return
            mine.sort(key=lambda i: -i["seen"])
            rows = [f"{'🚨 registered ' + i['registered'] if i['registered'] else '👀'} **{i['name']}** ({i['eco']}), asked for {i['seen']}×, first {i['first']}" for i in mine[:15]]
            await self.agent.send(ev.room_id, "**Names this team's agents invented:**\n" + "\n".join(rows))

    async def publish_on_start(self) -> None:
        """Once connected, make sure every room has its "Invented package names" document."""
        while not self.agent.connected:
            await asyncio.sleep(1)
        rooms = [r["room_id"] for r in (await self.agent.op("list_rooms", _bind=False) or []) if not r.get("archived")]
        for room_id in rooms:
            await self.sync_doc(room_id)

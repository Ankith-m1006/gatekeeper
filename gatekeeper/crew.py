"""What the crew shares, all of it through Switch.

Scout hands work to the others with one targeted Switch message (each teammate reads its own line).
Fixer keeps the room's rules and approvals in a Switch room document, the "Gatekeeper ledger", and
Scout reads it before every check. Nothing is passed inside the process, so each agent can run
on its own machine.
"""
from __future__ import annotations

import asyncio
import re
import json
import time
from pathlib import Path

from .registry import PackageReport  # noqa: F401  (type of key())

STATE = Path(__file__).resolve().parent.parent / "state"
CREW = {"scout", "inspector", "squat-watch", "fixer"}


# ---------------- per-room rules and approvals ----------------

DEFAULT_RULES = {
    "min_age_days": 30,        # younger than this needs a human approval
    "block_install_scripts": False,  # True: anything with an install script needs approval
}


class RoomPolicy:
    """Rules and approvals per room, kept on disk so they survive restarts."""

    def __init__(self) -> None:
        self.file = STATE / "rooms.json"
        self.data: dict = json.loads(self.file.read_text()) if self.file.exists() else {}

    def _room(self, room_id: str) -> dict:
        return self.data.setdefault(room_id, {"rules": dict(DEFAULT_RULES), "approved": {}})

    def save(self) -> None:
        STATE.mkdir(exist_ok=True)
        self.file.write_text(json.dumps(self.data, indent=1))

    def rules(self, room_id: str) -> dict:
        return {**DEFAULT_RULES, **self._room(room_id)["rules"]}

    def set_rule(self, room_id: str, key: str, value) -> None:
        self._room(room_id)["rules"][key] = value
        self.save()

    def approve(self, room_id: str, key: str, by: str) -> None:
        self._room(room_id)["approved"][key] = {"by": by, "at": time.strftime("%d %b %H:%M")}
        self.save()

    def revoke(self, room_id: str, key: str) -> bool:
        gone = self._room(room_id)["approved"].pop(key, None) is not None
        self.save()
        return gone

    def approval(self, room_id: str, key: str) -> dict | None:
        return self._room(room_id)["approved"].get(key)

    def approvals(self, room_id: str) -> dict:
        return self._room(room_id)["approved"]


def key(r: PackageReport) -> str:
    return f"{r.ecosystem}:{r.name}"


# ---------------- handoffs through Switch ----------------
# Scout hands work over with one targeted Switch message. Each teammate gets an addressed event
# and reads its own line; the humans in the room see the handoff as plain text.
SAYS = {"inspector": "Inspector", "squat-watch": "Squat Watch", "fixer": "Fixer"}
TOKEN = re.compile(r"`(npm|pypi):(@?[\w./-]+)`")


def handoff(asker: str, inspect: list[str], watch: list[str], install_text: str | None) -> tuple[list[str], str]:
    names, lines = [], []
    if inspect:
        names.append("inspector")
        lines.append("• Inspector, read " + ", ".join(f"`{k}`" for k in inspect))
    if watch:
        names.append("squat-watch")
        lines.append("• Squat Watch, watch " + ", ".join(f"`{k}`" for k in watch))
    if install_text:
        names.append("fixer")
        lines.append("• Fixer, make this safe:\n```\n" + install_text.strip() + "\n```")
    return names, f"Over to the crew ({asker}'s install):\n" + "\n".join(lines)


def my_part(body: str, agent: str) -> str | None:
    """The part of a handoff addressed to `agent`; Fixer's part runs to the end of the message."""
    who = SAYS[agent]
    i = body.find(f"• {who},")
    if i < 0:
        return None
    rest = body[i:]
    if agent != "fixer":
        rest = rest.split("\n", 1)[0]
    return rest


def asker_of(body: str) -> str:
    m = re.search(r"\((.+?)'s install\)", body)
    return m.group(1) if m else "someone"


def tokens(text: str) -> list[tuple[str, str]]:
    return [(e.lower(), n) for e, n in TOKEN.findall(text)]


# ---------------- the ledger: a Switch room document ----------------
LEDGER = "Gatekeeper ledger"


def ledger_text(room: dict) -> str:
    r = {**DEFAULT_RULES, **room.get("rules", {})}
    seen: dict[str, dict] = {}
    for k, v in room.get("approved", {}).items():
        seen.setdefault(k.split(":", 1)[1], v)
    lines = [
        "# Gatekeeper ledger",
        "Rules and approvals for this room. Fixer keeps this document; Scout reads it before every check.",
        "",
        "## Rules",
        f"- Packages younger than {r['min_age_days']} days need a person's approval.",
        f"- Packages that run a script on install need approval: {'yes' if r['block_install_scripts'] else 'no'}.",
        "",
        "## Approved packages",
    ]
    lines += [f"- {n}: approved by {v['by']} on {v['at']}" for n, v in seen.items()] or ["- none yet"]
    lines += ["", "```json", json.dumps({"rules": r, "approved": room.get("approved", {})}), "```"]
    return "\n".join(lines)


def parse_ledger(content: str | None) -> dict | None:
    if not content:
        return None
    m = re.search(r"```json\s*(\{.*\})\s*```", content, re.S)
    try:
        return json.loads(m.group(1)) if m else None
    except ValueError:
        return None

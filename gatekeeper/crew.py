"""What the crew shares: one case per checked install, plus per-room rules and approvals.

Each agent still has its own Switch identity and posts in the room as itself. The case board is
how they hand work to each other inside one process, so nobody has to parse another agent's prose.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from .registry import PackageReport

STATE = Path(__file__).resolve().parent.parent / "state"
CREW = {"scout", "inspector", "squat-watch", "fixer"}


@dataclass
class Case:
    room_id: str
    asked_by: str
    text: str
    reports: list[PackageReport]
    opened: float = field(default_factory=time.time)

    def worst(self) -> str:
        order = ["ok", "approved", "suspicious", "danger", "ghost"]
        return max((r.verdict for r in self.reports), key=order.index, default="ok")


Listener = Callable[[Case], Awaitable[None]]


class Board:
    """Scout opens cases; the rest of the crew picks them up."""

    def __init__(self) -> None:
        self._listeners: list[Listener] = []

    def subscribe(self, fn: Listener) -> None:
        self._listeners.append(fn)

    async def open(self, case: Case) -> None:
        # Small pause so Scout's verdict lands in the room before the follow-ups.
        await asyncio.sleep(1.5)
        await asyncio.gather(*(fn(case) for fn in self._listeners), return_exceptions=True)


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

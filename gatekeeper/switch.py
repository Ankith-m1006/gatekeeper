"""A small client for the Switch agent protocol (WebSocket events + HTTP operations).

Docs: https://docs.switchagents.ai/switch-rooms/internals/agent-protocol
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx
import websockets

log = logging.getLogger(__name__)

STATE_DIR = Path(__file__).resolve().parent.parent / "state"

Handler = Callable[["Event"], Awaitable[None]]


@dataclass
class Event:
    """One domain event from a room (message, command or room_join)."""

    type: str
    room_id: str
    payload: dict[str, Any]
    sequence: int

    @property
    def body(self) -> str:
        return str(self.payload.get("body") or "")

    @property
    def addressed(self) -> bool:
        return bool(self.payload.get("addressed"))

    @property
    def sender(self) -> str:
        return str(self.payload.get("sender_name") or self.payload.get("sender") or "")

    @property
    def message_id(self) -> str | None:
        return self.payload.get("message_id")


@dataclass
class Agent:
    """One Switch agent: registered once, then reconnects with the same id and key."""

    name: str
    description: str
    api: str
    registration_token: str
    display_name: str | None = None
    addressing: str = "anyone"
    filter: str = "all"
    agent_id: str = ""
    api_key: str = ""
    connection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    connected: bool = False
    current_room: str | None = None
    _http: httpx.AsyncClient | None = None
    _room_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # ---------- identity ----------
    def _state_file(self) -> Path:
        return STATE_DIR / f"{self.name}.json"

    async def ensure_registered(self) -> None:
        f = self._state_file()
        if f.exists():
            s = json.loads(f.read_text())
            self.agent_id, self.api_key = s["id"], s["api_key"]
            self.connection_id = s.get("connection_id", self.connection_id)
            return
        body = {
            "name": self.name,
            "description": self.description,
            "connector_type": "gatekeeper",
            "integration_profile": {
                "connection_model": "always_on",
                "message_exchange": True,
                "pre_invocation_mediation": [],
                "post_invocation_mediation": [],
                "event_reporting": [],
            },
        }
        if self.display_name:
            body["display_name"] = self.display_name
        async with httpx.AsyncClient(base_url=self.api, timeout=30) as c:
            auth = {"Authorization": f"Bearer {self.registration_token}"}
            r = await c.post("/agents", json=body, headers=auth)
            if r.status_code == 409:  # registered before but our key file is gone: issue a fresh key
                r = await c.post("/agents", json={**body, "overwrite": True}, headers=auth)
            r.raise_for_status()
            d = r.json()
        self.agent_id, self.api_key = d["id"], d["api_key"]
        STATE_DIR.mkdir(exist_ok=True)
        f.write_text(json.dumps({"id": self.agent_id, "api_key": self.api_key, "connection_id": self.connection_id}))
        try:
            await self.op("update_agent_detail", _bind=False, agent_id=self.agent_id, addressing=self.addressing)
        except RuntimeError as e:
            log.warning("could not set addressing for %s: %s", self.name, e)

    # ---------- operations ----------
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                base_url=self.api,
                timeout=30,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        return self._http

    async def op(self, name: str, _bind: bool = True, **args: Any) -> Any:
        """Call an operation. `_bind` sends the connection id so room-bound ops know the room."""
        headers = {"X-Switch-Connection-Id": self.connection_id} if (_bind and self.connected) else {}
        r = await self.http.post(f"/agents/{self.agent_id}/ops/{name}", json=args, headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(f"{name} -> {r.status_code}: {r.text[:300]}")
        return r.json().get("result")

    async def send(self, room_id: str, text: str) -> Any:
        """Post into a room without needing to switch this session's connected room."""
        r = await self.http.post(f"/agents/{self.agent_id}/message", json={"room_id": room_id, "content": text})
        if r.status_code >= 400:
            raise RuntimeError(f"message -> {r.status_code}: {r.text[:300]}")
        return r.json()

    # ---------- room-bound operations ----------
    async def _enter(self, room_id: str, force: bool = False) -> Any:
        """Point this session at a room (Switch resolves room-bound ops from it)."""
        if force or self.current_room != room_id:
            res = await self.op("connect_to_room", room_id=room_id, include_general_instructions=False)
            self.current_room = room_id
            return res
        return None

    async def in_room(self, room_id: str, name: str, **args: Any) -> Any:
        async with self._room_lock:
            await self._enter(room_id)
            return await self.op(name, **args)

    async def hand_off(self, room_id: str, names: list[str], body: str) -> Any:
        """Address teammates through Switch: they get an addressed event, the room sees the handoff."""
        return await self.in_room(room_id, "send_targeted_message", body=body, target_names=names)

    async def room_documents(self, room_id: str) -> list[dict]:
        async with self._room_lock:
            res = await self._enter(room_id, force=True)
        return (res or {}).get("documents") or [] if isinstance(res, dict) else []

    async def read_document(self, room_id: str, name: str) -> tuple[str | None, str | None]:
        """Return (document id, content) of the room document with this name, if any."""
        for d in await self.room_documents(room_id):
            if d.get("name") == name:
                got = await self.in_room(room_id, "load_internal_documents", ids=[d["id"]])
                return d["id"], (got[0].get("content") if got else None)
        return None, None

    async def write_document(self, room_id: str, doc_id: str | None, name: str, description: str, content: str) -> str:
        """Create or update a room document this agent owns; returns its id."""
        if doc_id:
            try:
                await self.in_room(room_id, "update_room_document", document_id=doc_id, content=content)
                return doc_id
            except RuntimeError as e:
                log.warning("%s could not update document %s, creating a new one: %s", self.name, doc_id, e)
        res = await self.in_room(room_id, "create_room_document", name=name, description=description,
                                 instructions="Kept up to date by the Gatekeeper crew. Read it; do not edit by hand.", content=content)
        return (res or {}).get("id") or (res or {}).get("document_id") or ""

    # ---------- events ----------
    async def run(self, handler: Handler, rooms: list[str] | None = None) -> None:
        """Connect, answer pings, hand domain events to `handler`, reconnect forever."""
        ws_base = self.api.replace("https://", "wss://").replace("http://", "ws://")
        cursor: Any = "head"
        generation: int | None = None
        while True:
            if not rooms:  # claim every room this agent belongs to
                rooms = [r["room_id"] for r in (await self.op("list_rooms", _bind=False) or []) if not r.get("archived")]
            qs = f"connection_id={self.connection_id}&scope=all&filter={self.filter}&start_from={cursor}"
            if rooms:
                qs += "&rooms=" + ",".join(rooms)
            if generation is not None:
                qs += f"&expected_generation={generation}"
            url = f"{ws_base}/agents/{self.agent_id}/connection/ws?{qs}"
            try:
                async with websockets.connect(url, additional_headers={"Authorization": f"Bearer {self.api_key}"}) as ws:
                    async for raw in ws:
                        frame = json.loads(raw)
                        kind = frame.get("event") or frame.get("type")
                        data = frame.get("data") if isinstance(frame.get("data"), dict) else frame
                        if kind == "ping":
                            await ws.send(json.dumps({"type": "pong", "cursor": cursor if isinstance(cursor, int) else 0}))
                        elif kind == "connection_state":
                            generation = data.get("generation", generation)
                            self.connected = True
                            self.current_room = None  # a new connection starts unbound
                            log.info("%s connected: rooms=%s", self.name, data.get("rooms"))
                        elif kind == "gap":
                            cursor = data.get("resumed_at", cursor)
                        elif kind == "evicted":
                            log.warning("%s evicted: %s", self.name, data)
                            if data.get("code") == "taken_over":
                                return
                            break
                        elif kind in ("message", "command", "room_join"):
                            ev = Event(kind, data.get("room_id", ""), data.get("payload") or {}, int(frame.get("id") or data.get("sequence") or 0))
                            cursor = ev.sequence
                            asyncio.create_task(self._safe(handler, ev))
            except websockets.ConnectionClosed as e:
                code = e.rcvd.code if e.rcvd else None
                log.warning("%s socket closed (%s)", self.name, code)
                if code in (4400, 4401):
                    raise
            except OSError as e:
                log.warning("%s connect failed: %s", self.name, e)
            self.connected = False
            await asyncio.sleep(2)

    async def _safe(self, handler: Handler, ev: Event) -> None:
        try:
            await handler(ev)
        except Exception:  # one bad event must never kill the agent
            log.exception("%s handler failed on event %s", self.name, ev.sequence)

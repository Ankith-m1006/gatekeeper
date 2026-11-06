"""Gatekeeper as a Switch guardrail: enforcement in the message path, not in a prompt.

Switch calls `POST {endpoint}/guardrails/check` before it delivers a message that a person or an agent
wrote (Switch Trust, see docs/design/switch-trust-guardrails-v1.md in the Switch repo). The answer decides
what happens to that message:

- a credential (API key, token, private key, password in a connection string) is REDACTED: Switch replaces
  it with [redacted] before the room, the bridged channels or any agent see it, and tells the sender;
- invisible characters that hide instructions (Unicode tag characters, zero-width and bidi controls) are
  REDACTED the same way, so a hidden line pasted into chat never reaches a coding agent;
- everything else is OK. Package verdicts stay with Scout, which answers in the room with the evidence.

It is a tiny HTTP server on the stdlib (no new dependency) that runs next to the crew. The API key Switch
sends in `x-flintai-api-key` must match GUARDRAIL_KEY.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os

from .agent_guard import BIDI, PLACEHOLDER, SECRETS, TAGS, ZERO_WIDTH

log = logging.getLogger(__name__)



def _hidden_runs(text: str) -> list[str]:
    """Runs of invisible characters, except the tag letters inside an emoji subdivision flag (🏴 England etc.)."""
    runs, cur, in_flag, prev = [], [], False, None
    for ch in text:
        cp = ord(ch)
        if cp in TAGS:
            if in_flag or (not cur and prev == 0x1F3F4):
                in_flag = cp != 0xE007F
                prev = cp
                continue
            cur.append(ch)
        elif cp in ZERO_WIDTH or cp in BIDI:
            # A lone zero-width joiner inside an emoji sequence (👩‍💻) is normal text.
            if cp == 0x200D and prev is not None and prev >= 0x1F000:
                prev = cp
                continue
            cur.append(ch)
        else:
            if cur:
                runs.append("".join(cur))
                cur = []
            in_flag = False
        prev = cp
    if cur:
        runs.append("".join(cur))
    return runs


def check(content: str) -> dict:
    """The Switch Trust response body for one message."""
    findings: list[dict] = []
    for kind, rx in SECRETS:
        for m in rx.finditer(content):
            val = m.group(0)
            if PLACEHOLDER.search(val) or (kind == "OpenAI API key" and val.startswith("sk-ant-")):
                continue
            findings.append({"category": "secret", "detector_name": f"gatekeeper/{kind}", "severity": "high", "detected_string": val})
    for run in _hidden_runs(content):
        findings.append({"category": "hidden-instructions", "detector_name": "gatekeeper/invisible-characters",
                         "severity": "high" if any(ord(c) in TAGS for c in run) else "medium", "detected_string": run})
    outcome = "GUARDRAIL_RESULT_OUTCOME_REDACTED" if findings else "GUARDRAIL_RESULT_OUTCOME_OK"
    return {"outcome": outcome, "policy_id": "gatekeeper", "policy_name": "Gatekeeper", "findings": findings}


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, key: str) -> None:
    status, body = 200, {}
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
        raw = await asyncio.wait_for(reader.readexactly(int(headers.get("content-length", "0"))), 5)
        if method == "GET" and path == "/health":
            body = {"ok": True}
        elif method != "POST" or path.rstrip("/") != "/guardrails/check":
            status, body = 404, {"error": "not found"}
        elif not hmac.compare_digest(headers.get("x-flintai-api-key", ""), key):
            status, body = 401, {"error": "bad api key"}
        else:
            msgs = json.loads(raw or b"{}").get("messages") or []
            content = "\n".join(str(m.get("content", "")) for m in msgs if isinstance(m, dict))
            body = check(content)
            if body["findings"]:
                log.info("guardrail: redacted %s in room %s", ",".join(sorted({f["category"] for f in body["findings"]})),
                         headers.get("x-agent-session-id", "?"))
    except Exception as e:  # a malformed request gets a 400; Switch then fails open and annotates the message
        status, body = 400, {"error": str(e)[:200]}
    data = json.dumps(body).encode()
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}[status]
    writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
    try:
        await writer.drain()
    finally:
        writer.close()


async def serve(host: str | None = None, port: int | None = None, key: str | None = None) -> None:
    host = host or os.environ.get("GUARDRAIL_HOST", "127.0.0.1")
    port = port or int(os.environ.get("GUARDRAIL_PORT", "8790"))
    key = key or os.environ.get("GUARDRAIL_KEY", "")
    if not key:
        log.warning("GUARDRAIL_KEY is not set: the Switch guardrail is off")
        return
    server = await asyncio.start_server(lambda r, w: _handle(r, w, key), host, port)
    log.info("guardrail listening on %s:%s", host, port)
    async with server:
        await server.serve_forever()

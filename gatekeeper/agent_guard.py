"""Checks for what coding agents read and say, beyond packages.

Four kinds of trouble, all found without running anything and without a model call:

1. Hidden instructions: invisible Unicode (the Tags block, zero-width and bidi characters) that a
   person never sees but an AI agent reads, as in the "Rules File Backdoor" attack on agent rules
   files. Tags-block text is decoded so the room can see what was hidden.
2. Agent-directed instructions in plain sight: text in a rules file or an MCP tool description that
   tells the agent to act behind the user's back ("don't tell the user", "read ~/.ssh and pass it").
3. Secrets pasted into the room by a person or printed by an agent.
4. Dangerous commands a coding agent proposes (pipe-to-shell, rm -rf ~, force push, DROP TABLE).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# ---------------- 1. invisible characters ----------------

TAGS = range(0xE0000, 0xE0080)  # Unicode Tags block: invisible, maps 1:1 to ASCII
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F}


@dataclass
class Hidden:
    tags: int = 0
    zero_width: int = 0
    bidi: int = 0
    decoded: list[str] = field(default_factory=list)  # Tags-block runs turned back into text
    lines: list[int] = field(default_factory=list)

    @property
    def found(self) -> bool:
        # A lone zero-width joiner shows up in emoji; only count real amounts.
        return bool(self.tags or self.bidi or self.zero_width >= 3)


def hidden_text(text: str) -> Hidden:
    h = Hidden()
    run: list[str] = []
    line = 1
    prev, in_flag = 0, False
    for ch in text:
        cp = ord(ch)
        last, prev = prev, cp
        if ch == "\n":
            line += 1
        if cp in TAGS:
            # Emoji subdivision flags (🏴 + tag letters + cancel tag, e.g. England) are normal text.
            if in_flag or (not run and last == 0x1F3F4):
                in_flag = cp != 0xE007F
                continue
            h.tags += 1
        else:
            in_flag = False
        if cp in TAGS:
            if 0xE0020 <= cp <= 0xE007E:
                run.append(chr(cp - 0xE0000))
            if line not in h.lines:
                h.lines.append(line)
            continue
        if run:
            h.decoded.append("".join(run))
            run = []
        if cp in ZERO_WIDTH:
            h.zero_width += 1
            if line not in h.lines and h.zero_width >= 3:
                h.lines.append(line)
        elif cp in BIDI:
            h.bidi += 1
            if line not in h.lines:
                h.lines.append(line)
    if run:
        h.decoded.append("".join(run))
    h.decoded = [d.strip() for d in h.decoded if d.strip()]
    return h


def strip_hidden(text: str) -> str:
    return "".join(ch for ch in text if ord(ch) not in TAGS and ord(ch) not in ZERO_WIDTH and ord(ch) not in BIDI)


# ---------------- 2. instructions aimed at the agent ----------------

AGENT_RULES: list[tuple[str, re.Pattern]] = [
    ("tells the agent to hide what it does", re.compile(r"\b(do not|don'?t|never)\s+(tell|mention|inform|alert|notify)\b[^.\n]{0,40}\bthe\s+(user|human|developer)\b|without\s+(telling|asking|informing|notifying)\s+the\s+(user|human|developer)|\bsilently\b[^.\n]{0,60}\b(add|run|install|send|insert|include|execute)", re.I)),
    ("tries to override the agent's instructions", re.compile(r"\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|prompts?)|\bdisregard\s+(all\s+|the\s+)?(previous|prior|above)\b|\byou\s+are\s+now\s+(a|an|in)\b|\bnew\s+system\s+prompt\b", re.I)),
    ("asks the agent to read secrets or keys", re.compile(r"\b(read|open|cat|load|include|pass|send|attach|copy)\b[^.\n]{0,60}(~/\.ssh|id_rsa|id_ed25519|\.env\b|\.npmrc|\.aws/credentials|\.netrc|private key|api[_ ]?keys?|access tokens?)", re.I)),
    ("asks the agent to send data somewhere", re.compile(r"\b(send|post|upload|exfiltrate|forward|transmit)\b[^.\n]{0,60}\b(to|at)\s+(https?://|[\w-]+\.(?:com|net|io|xyz|site|app|dev)\b)", re.I)),
    ("tells the agent to download and run code", re.compile(r"(curl|wget)[^\n|;]{0,200}\|\s*(ba|z)?sh\b|Invoke-WebRequest[^\n]{0,200}(iex|Invoke-Expression)", re.I)),
    ("hides an instruction block inside a tool description", re.compile(r"<\s*(IMPORTANT|SYSTEM|SECRET|HIDDEN)\s*>")),  # upper case: AWS docs use HTML <important>
]


def agent_instructions(text: str) -> list[tuple[str, int, str]]:
    """(label, line, snippet) for text that instructs an agent to act against its user."""
    out = []
    for label, rx in AGENT_RULES:
        m = rx.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            # the sentence around the match, on one line, cut at word edges
            start = max(text.rfind(". ", 0, m.start()), text.rfind("\n\n", 0, m.start()), text.rfind(">", 0, m.start() - 1), m.start() - 80)
            end = min([i for i in (text.find(". ", m.end()), text.find(".\n", m.end()), text.find("<", m.end()), m.end() + 80) if i >= 0])
            snip = re.sub(r"\s+", " ", text[start + 1: end + 1]).strip(" \"'.")
            out.append((label, line, snip[:140]))
    return out


# Files a coding agent reads as instructions or tool definitions.
INSTRUCTION_FILES = re.compile(
    r"(^|/)(claude|agents|gemini|copilot-instructions|skill|rules|instructions|system[-_]?prompt|prompt)\.md$"
    r"|(^|/)\.(cursorrules|windsurfrules|clinerules|aider\.conf\.yml)$|\.mdc$"
    r"|(^|/)(\.?mcp|claude_desktop_config|mcp_config|settings)\.json$",
    re.I,
)
CODE_FILES = re.compile(r"\.(py|js|mjs|cjs|ts)$", re.I)


def is_instruction_file(name: str) -> bool:
    return bool(INSTRUCTION_FILES.search(name.lower()))


def is_code_file(name: str) -> bool:
    return bool(CODE_FILES.search(name))


def clean_lines(text: str) -> tuple[str, int]:
    """The file without invisible characters or lines that instruct the agent against the user.

    Returns (cleaned text, number of lines removed).
    """
    keep, dropped = [], 0
    # A whole <IMPORTANT>...</IMPORTANT> block in a tool description goes, tags included.
    def cut(m: re.Match) -> str:
        nonlocal dropped
        dropped += m.group(0).count("\n") + 1
        return ""
    text = re.sub(r"[ \t]*<\s*(IMPORTANT|SYSTEM|secret|hidden)\s*>.*?<\s*/\s*\1\s*>[ \t]*\n?", cut, text, flags=re.S | re.I)
    for raw in text.splitlines():
        had_hidden = hidden_text(raw).tags > 0
        line = strip_hidden(raw)
        if had_hidden and not line.strip():
            dropped += 1
            continue
        if any(rx.search(line) for _, rx in AGENT_RULES):
            dropped += 1
            continue
        keep.append(line)
    return "\n".join(keep), dropped


# ---------------- MCP servers ----------------

MCP_ADD = re.compile(r"\b(?:claude|codex|gemini)\s+mcp\s+add\b[^\n`]*", re.I)


def mcp_packages_in_config(text: str) -> list[tuple[str, str]]:
    """Packages an MCP config (mcp.json, claude_desktop_config.json) would launch with npx or uvx."""
    try:
        d = json.loads(text)
    except ValueError:
        return []
    servers = d.get("mcpServers") or d.get("servers") or (d.get("mcp") or {}).get("servers") or {}
    found: list[tuple[str, str]] = []
    for s in servers.values() if isinstance(servers, dict) else []:
        cmd = str(s.get("command", "")).rsplit("/", 1)[-1].lower()
        args = [str(a) for a in s.get("args") or []]
        names = [a for a in args if not a.startswith("-")]
        if not names:
            continue
        if cmd in ("npx", "npx.cmd", "bunx", "pnpm", "yarn"):
            pkg = names[0] if cmd != "pnpm" else (names[1] if len(names) > 1 else "")
            pkg = re.sub(r"(?<=.)@[^/@]*$", "", pkg)  # drop @version
            if pkg and ("npm", pkg) not in found:
                found.append(("npm", pkg))
        elif cmd in ("uvx", "pipx"):
            pkg = re.split(r"[=<>@\[]", names[-1] if cmd == "pipx" else names[0])[0]
            if pkg and ("pypi", pkg) not in found:
                found.append(("pypi", pkg))
    return found


# ---------------- 3. secrets ----------------

SECRETS: list[tuple[str, re.Pattern]] = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("password in a connection string", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]{4,}@", re.I)),
]
PLACEHOLDER = re.compile(r"x{6,}|\.\.\.|<[^>]+>|your[_-]?(key|token)|example|dummy|changeme", re.I)


def redact(s: str) -> str:
    return s[:6] + "…" + s[-2:] if len(s) > 12 else s[:3] + "…"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """(kind, redacted value) for credentials in the text. Placeholders are ignored."""
    out: list[tuple[str, str]] = []
    for kind, rx in SECRETS:
        for m in rx.finditer(text):
            val = m.group(0)
            if PLACEHOLDER.search(val):
                continue
            if kind == "OpenAI API key" and val.startswith("sk-ant-"):
                continue
            item = (kind, redact(val))
            if item not in out:
                out.append(item)
    return out


# ---------------- 4. dangerous commands ----------------

COMMANDS: list[tuple[str, str, re.Pattern]] = [
    ("downloads a script and runs it unseen", "download it, read it, then run the file: `curl -fsSLo install.sh <url>` then `less install.sh`",
     re.compile(r"(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|\biex\s*\(\s*(irm|iwr|Invoke-WebRequest|New-Object\s+Net\.WebClient)", re.I)),
    ("deletes a home, root or parent folder", "name the exact folder inside the project, e.g. `rm -rf ./build`",
     re.compile(r"\brm\s+(?:-\w+\s+)*-\w*[rR]\w*\s+(?:-\w+\s+)*(?:/|~|\$HOME|\.\.)(?:/?\*)?/?(?=\s|$|;|&|`)")),
    ("force-pushes over shared history", "push to a branch and open a PR, or use `git push --force-with-lease` on your own branch",
     re.compile(r"\bgit\s+push\b[^\n]*(\s--force\b(?!-with-lease)|\s-f\b)", re.I)),
    ("drops a database or table", "back it up first and run it against a local copy",
     re.compile(r"\bDROP\s+(DATABASE|TABLE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b", re.I)),
    ("turns off TLS certificate checks", "fix the certificate instead; never ship with checks off",
     re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|verify\s*=\s*False|--insecure\b|\bcurl\s+[^\n]*\s-k\b|strict-ssl\s+false", re.I)),
    ("makes files writable by everyone", "give only the access needed, e.g. `chmod 755` or `chmod 644`",
     re.compile(r"\bchmod\s+(-R\s+)?0?777\b", re.I)),
    ("skips the project's safety hooks", "let the hooks run, or fix what they report",
     re.compile(r"\bgit\s+(commit|push)\b[^\n]*\s--no-verify\b", re.I)),
]


def dangerous_commands(text: str) -> list[tuple[str, str, str]]:
    """(what it does, safer way, the command) for risky shell commands in the text."""
    out = []
    for label, safer, rx in COMMANDS:
        m = rx.search(text)
        if m:
            end = text.find("\n", m.end())
            cmd = text[m.start(): end if end >= 0 else len(text)].split("`")[0].strip()
            out.append((label, safer, cmd[:160]))
    return out

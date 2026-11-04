"""Find the packages someone is about to install in a chat message (or a coding agent's answer)."""
from __future__ import annotations

import re

# Commands that add a dependency, per ecosystem.
_NPM = re.compile(r"\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:add|i|install)|bun\s+(?:add|i|install)|npx)\s+([^\n`;&|]+)", re.I)
_PIP = re.compile(r"\b(?:pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+(?:add|pip\s+install)|poetry\s+add|pipenv\s+install)\s+([^\n`;&|]+)", re.I)

# A whole line that installs something, for rewriting and handing over.
INSTALL_LINE = re.compile(r"^.*\b(npm|yarn|pnpm|bun|npx|pip3?|uv|poetry|pipenv|python3?\s+-m\s+pip)\b.*$", re.I | re.M)

_NPM_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _clean_npm(tok: str) -> str | None:
    tok = tok.strip().strip("'\"")
    if not tok or tok.startswith("-") or "://" in tok or tok.startswith((".", "/", "file:", "git")):
        return None
    # strip a version: lodash@4, @scope/pkg@^1
    if tok.startswith("@"):
        parts = tok.split("@")
        tok = "@" + parts[1] if len(parts) > 1 else tok
    else:
        tok = tok.split("@")[0]
    return tok.lower() if _NPM_NAME.match(tok) else None


def _clean_py(tok: str) -> str | None:
    tok = tok.strip().strip("'\"")
    if not tok or tok.startswith("-") or "://" in tok or tok.startswith((".", "/")) or tok.endswith((".txt", ".whl", ".tar.gz")):
        return None
    tok = re.split(r"[\[<>=!~;]", tok)[0]
    return tok if _PY_NAME.match(tok) else None


def packages_in(text: str) -> list[tuple[str, str]]:
    """Return [(ecosystem, name)] in the order they appear, without duplicates."""
    found: list[tuple[str, str]] = []
    for rx, eco, clean in ((_NPM, "npm", _clean_npm), (_PIP, "pypi", _clean_py)):
        for m in rx.finditer(text):
            for tok in m.group(1).split():
                if tok in ("-r", "--requirement"):
                    break
                name = clean(tok)
                if name and (eco, name) not in found:
                    found.append((eco, name))
    return found

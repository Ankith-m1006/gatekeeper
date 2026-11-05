"""Find the packages someone is about to install in a chat message (or a coding agent's answer)."""
from __future__ import annotations

import re

# Commands that add a dependency, per ecosystem.
_NPM = re.compile(r"\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:add|i|install)|bun\s+(?:add|i|install)|npx)\s+([^\n`;&|]+)", re.I)
_PIP = re.compile(r"\b(?:pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+(?:add|pip\s+install)|poetry\s+add|pipenv\s+install|uvx|pipx\s+(?:run|install))\s+([^\n`;&|]+)", re.I)

# A whole line that installs something, for rewriting and handing over.
INSTALL_LINE = re.compile(r"^.*\b(npm|yarn|pnpm|bun|npx|pip3?|pipx|uvx?|poetry|pipenv|python3?\s+-m\s+pip)\b.*$", re.I | re.M)

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


# ---------- dependency files dropped into the chat ----------
DEP_FILES = ("package.json", "package-lock.json", "requirements", "pyproject.toml", "pipfile")


def is_dep_file(filename: str) -> bool:
    f = filename.lower().rsplit("/", 1)[-1]
    return f in ("package.json", "package-lock.json", "pyproject.toml", "pipfile") or (f.startswith("requirements") and f.endswith((".txt", ".in")))


def packages_in_file(filename: str, text: str) -> list[tuple[str, str]]:
    """Dependencies declared in a package.json, package-lock.json, requirements*.txt, pyproject.toml or Pipfile."""
    import json

    f = filename.lower().rsplit("/", 1)[-1]
    found: list[tuple[str, str]] = []

    def add(eco: str, raw: str) -> None:
        name = (_clean_npm if eco == "npm" else _clean_py)(raw)
        if name and (eco, name) not in found:
            found.append((eco, name))

    if f in ("package.json", "package-lock.json"):
        try:
            d = json.loads(text)
        except ValueError:
            return found
        if f == "package-lock.json":  # only what the project itself asks for, not the whole tree
            d = (d.get("packages") or {}).get("") or d
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name in (d.get(section) or {}):
                add("npm", name)
    elif f.startswith("requirements"):
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith(("-", "git+", "http")):
                add("pypi", line)
    elif f == "pyproject.toml":
        # PEP 621 `dependencies = [...]` and Poetry `[tool.poetry.dependencies]` tables, without a TOML parser
        for block in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.S):
            for raw in re.findall(r"['\"]([^'\"]+)['\"]", block):
                add("pypi", raw)
        for table in re.findall(r"\[tool\.poetry\.(?:group\.\w+\.)?dependencies\]\s*\n(.*?)(?:\n\[|\Z)", text, re.S):
            for name in re.findall(r"^\s*([A-Za-z0-9][\w.-]*)\s*=", table, re.M):
                if name.lower() != "python":
                    add("pypi", name)
    elif f == "pipfile":
        for table in re.findall(r"\[(?:dev-)?packages\]\s*\n(.*?)(?:\n\[|\Z)", text, re.S):
            for name in re.findall(r"^\s*([A-Za-z0-9][\w.-]*)\s*=", table, re.M):
                add("pypi", name)
    return found


_COMMAND = re.compile(
    r"\b(?:npm|yarn|pnpm|bun|npx|pip3?|pipx|uvx?|poetry|pipenv|python3?\s+-m\s+pip)\b[^`\n]*", re.I
)
_MENTION = re.compile(r"<@[&!]?\d+>|@[\w-]+")


def install_commands(text: str) -> str:
    """Just the install commands from a message, without mentions or the sentence around them."""
    out = []
    for m in INSTALL_LINE.finditer(_MENTION.sub("", text)):
        c = _COMMAND.search(m.group(0))
        if c:
            cmd = re.split(r"(?<=\S)[.,;:!?)]\s|\s\(|\.\s*$", c.group(0).strip(), maxsplit=1)[0].strip().rstrip(".,;:")
            if cmd and cmd not in out:
                out.append(cmd)
    return "\n".join(out)

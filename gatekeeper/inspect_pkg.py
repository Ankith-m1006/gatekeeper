"""Read a published package's files and look for the things malware does.

Nothing is installed, extracted to disk, imported or executed. The archive is downloaded into
memory, and only text files under a size cap are read as strings.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field

import httpx

from .registry import UA

MAX_ARCHIVE = 25 * 1024 * 1024     # bytes downloaded
MAX_FILE = 2 * 1024 * 1024          # bytes read per file
MAX_TOTAL = 40 * 1024 * 1024        # bytes read across the archive (zip bomb guard)
TEXT = (".js", ".cjs", ".mjs", ".ts", ".json", ".py", ".sh", ".bat", ".ps1", ".cfg", ".toml", ".txt")

# (severity, label, regex). severity: 3 = high, 2 = medium, 1 = low
RULES: list[tuple[int, str, re.Pattern]] = [
    (3, "reads SSH keys, npm tokens or cloud credentials", re.compile(r"\.ssh[/\\]id_|\.npmrc|\.pypirc|\.aws[/\\]credentials|\.docker[/\\]config\.json|\.kube[/\\]config", re.I)),
    (3, "touches browser or crypto-wallet data", re.compile(r"Login Data|Local State|\.config[/\\](google-chrome|BraveSoftware)|Exodus|MetaMask|electrum|wallet\.dat", re.I)),
    (3, "sends data to a Discord or Telegram webhook", re.compile(r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot", re.I)),
    (3, "downloads something and runs it", re.compile(r"(curl|wget)[^\n|;]{0,200}\|\s*(ba)?sh|Invoke-WebRequest[^\n]{0,200}(iex|Invoke-Expression)|powershell[^\n]{0,80}-enc", re.I)),
    (2, "decodes a hidden base64 payload", re.compile(r"(atob|b64decode|Buffer\.from)\s*\(\s*['\"][A-Za-z0-9+/=]{120,}")),
    (2, "builds and runs code at runtime", re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(compile|base64|zlib|marshal)|marshal\.loads|__import__\(['\"]base64")),
    (2, "runs shell commands", re.compile(r"child_process|\bexecSync\s*\(|\bspawn\s*\(|subprocess\.(Popen|call|run|check_output)|os\.system\s*\(")),
    (2, "talks to a raw IP address", re.compile(r"https?://(?!127\.0\.0\.1|0\.0\.0\.0|localhost)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
    (2, "collects environment variables in bulk", re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)")),
    (1, "looks obfuscated", re.compile(r"_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){40,}", re.I)),
    (1, "fingerprints the machine", re.compile(r"os\.(hostname|userInfo|networkInterfaces)\(\)|platform\.node\(\)|getpass\.getuser\(\)")),
]

# Files that run without anyone calling the package: install hooks and Python build scripts.
# Test suites and docs are never loaded by an install, so they don't count.
SKIP = re.compile(r"(^|/)(tests?|__tests__|spec|specs|docs?|examples?|benchmarks?|fixtures?)/|(^|/)test_[^/]*\.py$|\.(test|spec)\.[cm]?[jt]s$", re.I)
AUTORUN = re.compile(r"(^|/)(setup\.py|__init__\.py|install\.js|preinstall\.js|postinstall\.js)$")


@dataclass
class Finding:
    severity: int
    label: str
    file: str
    line: int
    snippet: str
    autorun: bool


@dataclass
class Inspection:
    ecosystem: str
    name: str
    version: str | None = None
    files_read: int = 0
    install_scripts: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def score(self) -> int:
        s = sum(f.severity * (2 if f.autorun else 1) for f in self.findings)
        if self.install_scripts:
            s += 2
        return s

    @property
    def verdict(self) -> str:
        if self.error:
            return "unknown"
        high = any(f.severity == 3 for f in self.findings)
        if high or self.score >= 8:
            return "malicious-looking"
        if self.score >= 3:
            return "risky"
        return "clean"


async def _archive_url(c: httpx.AsyncClient, eco: str, name: str) -> tuple[str, str]:
    if eco == "npm":
        r = await c.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest", headers=UA)
        r.raise_for_status()
        d = r.json()
        return d["dist"]["tarball"], d.get("version", "")
    r = await c.get(f"https://pypi.org/pypi/{name}/json", headers=UA)
    r.raise_for_status()
    d = r.json()
    files = d.get("urls") or []
    # Prefer the sdist: setup.py lives there and runs at install time.
    files.sort(key=lambda f: 0 if f.get("packagetype") == "sdist" else 1)
    if not files:
        raise ValueError("no files published for the latest version")
    return files[0]["url"], d["info"]["version"]


def _members(blob: bytes, url: str):
    """Yield (path, text) for small text files, never touching the disk."""
    total = 0
    if url.endswith((".whl", ".zip")):
        z = zipfile.ZipFile(io.BytesIO(blob))
        for i in z.infolist():
            if i.is_dir() or i.file_size > MAX_FILE or not i.filename.endswith(TEXT):
                continue
            total += i.file_size
            if total > MAX_TOTAL:
                return
            yield i.filename, z.read(i).decode("utf-8", "replace")
        return
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
        for m in t:
            if not m.isfile() or m.size > MAX_FILE or not m.name.endswith(TEXT):
                continue
            total += m.size
            if total > MAX_TOTAL:
                return
            f = t.extractfile(m)  # a file object in memory, not an extraction to disk
            if f:
                yield m.name, f.read().decode("utf-8", "replace")


def scan_text(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    auto = bool(AUTORUN.search(path))
    for sev, label, rx in RULES:
        m = rx.search(text)
        if not m:
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = text[max(0, m.start() - 30): m.end() + 30].replace("\n", " ").strip()
        out.append(Finding(sev, label, path.split("/", 1)[-1], line, snippet[:120], auto))
    return out


async def inspect(eco: str, name: str) -> Inspection:
    res = Inspection(eco, name)
    try:
        async with httpx.AsyncClient(timeout=40, follow_redirects=True) as c:
            url, res.version = await _archive_url(c, eco, name)
            async with c.stream("GET", url, headers=UA) as r:
                r.raise_for_status()
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_ARCHIVE:
                        raise ValueError("archive is larger than 25 MB, not reading it")
        for path, text in _members(bytes(buf), url):
            res.files_read += 1
            if SKIP.search(path):
                continue
            if path.endswith("package.json") and path.count("/") <= 1:
                try:
                    scripts = json.loads(text).get("scripts") or {}
                    res.install_scripts = {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")}
                    for cmd in res.install_scripts.values():  # the hook command itself
                        res.findings += scan_text("package.json (install hook)", cmd)
                except ValueError:
                    pass
            res.findings += scan_text(path, text)
    except Exception as e:  # report, never crash the agent
        res.error = str(e)[:200]
    # One line per label is enough for a chat message; keep the worst instance.
    best: dict[str, Finding] = {}
    for f in sorted(res.findings, key=lambda f: (-f.severity, not f.autorun)):
        best.setdefault(f.label, f)
    res.findings = list(best.values())
    return res

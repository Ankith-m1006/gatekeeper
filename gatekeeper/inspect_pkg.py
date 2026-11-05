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

from .agent_guard import agent_instructions, hidden_text
from .registry import UA

MAX_ARCHIVE = 25 * 1024 * 1024     # bytes downloaded
MAX_FILE = 2 * 1024 * 1024          # bytes read per file
MAX_TOTAL = 40 * 1024 * 1024        # bytes read across the archive (zip bomb guard)
TEXT = (".js", ".cjs", ".mjs", ".ts", ".json", ".py", ".sh", ".bat", ".ps1", ".cfg", ".toml", ".txt", ".md")

# (severity, label, regex). severity: 3 = high, 2 = medium, 1 = low
RULES: list[tuple[int, str, re.Pattern]] = [
    (2, "reads SSH keys, npm tokens or cloud credentials", re.compile(r"\.ssh[/\\]id_|\.npmrc|\.pypirc|\.aws[/\\]credentials|\.docker[/\\]config\.json|\.kube[/\\]config", re.I)),
    # Case-sensitive and path-shaped, so "local state" in normal prose does not count.
    (3, "touches browser or crypto-wallet data", re.compile(r"[/\\]Login Data\b|[/\\]Local State\b|\.config[/\\](google-chrome|BraveSoftware|discord)|(Google[/\\]Chrome|BraveSoftware|Exodus|Electrum|atomic)[/\\](User Data|exodus\.wallet|wallets|Local Storage)|nkbihfbeogaeaoehlefnkodbefgpgknn|wallet\.dat\b")),
    (3, "sends data to a Discord or Telegram webhook", re.compile(r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot", re.I)),
    (3, "downloads something and runs it", re.compile(r"(curl|wget)[^\n|;]{0,200}\|\s*(ba)?sh|Invoke-WebRequest[^\n]{0,200}(iex|Invoke-Expression)|powershell[^\n]{0,80}-enc", re.I)),
    (2, "decodes a hidden base64 payload", re.compile(r"(atob|b64decode|Buffer\.from)\s*\(\s*['\"][A-Za-z0-9+/=]{120,}")),
    (3, "decodes hidden code and runs it", re.compile(r"\b(exec|eval)\s*\(\s*(base64\.|b64decode|zlib\.|marshal\.|codecs\.decode|bytes\.fromhex|__import__\(['\"](base64|zlib|marshal)|Buffer\.from\([^)]{0,200}['\"](base64|hex)['\"])")),
    (2, "builds and runs code at runtime", re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(compile|base64|zlib|marshal)|marshal\.loads|__import__\(['\"]base64")),
    (2, "runs shell commands", re.compile(r"child_process|\bexecSync\s*\(|\bspawn\s*\(|subprocess\.(Popen|call|run|check_output)|os\.system\s*\(")),
    (2, "talks to a raw IP address", re.compile(r"https?://(?!127\.0\.0\.1|0\.0\.0\.0|localhost)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
    (2, "collects environment variables in bulk", re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)")),
    (1, "looks obfuscated", re.compile(r"_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){40,}", re.I)),
    (1, "fingerprints the machine", re.compile(r"os\.(hostname|userInfo|networkInterfaces)\(\)|platform\.node\(\)|getpass\.getuser\(\)")),
]

# Files that run without anyone calling the package: install hooks and Python build scripts.
# Test suites and docs are never loaded by an install, so they don't count.
SKIP = re.compile(r"(^|/)(tests?|testing|__tests__|spec|specs|docs?|examples?|benchmarks?|fixtures?|\.github|\.circleci|ci|tools|vendor|vendored|third_party|build_tools|meson_cpu)/|(^|/)test_[^/]*\.py$|\.(test|spec)\.[cm]?[jt]s$", re.I)
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
        if any(f.severity == 3 for f in self.findings):
            return "malicious-looking"
        # Risky = something runs at install/import time, or many medium signals pile up.
        if self.install_scripts or any(f.autorun and f.severity >= 2 for f in self.findings) or self.score >= 6:
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


ARCHIVE = (".tgz", ".tar.gz", ".whl", ".zip", ".tar.bz2")


def _members(blob: bytes, url: str, pwd: bytes | None = None, depth: int = 0):
    """Yield (path, text) for small text files, never touching the disk.

    Archives inside archives (a sample zip holding an sdist) are opened in memory too.
    """
    budget = [MAX_TOTAL]

    def take(size: int) -> bool:
        budget[0] -= size
        return budget[0] >= 0

    def nested(name: str, data: bytes):
        if depth < 2 and len(data) <= MAX_ARCHIVE:
            try:
                yield from _members(data, name, None, depth + 1)
            except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, RuntimeError):
                return  # a broken or encrypted inner archive is skipped, not fatal

    if url.endswith((".whl", ".zip")):
        z = zipfile.ZipFile(io.BytesIO(blob))
        for i in z.infolist():
            if i.is_dir():
                continue
            if i.filename.endswith(ARCHIVE):
                yield from nested(i.filename, z.read(i, pwd=pwd))
                continue
            if i.file_size > MAX_FILE or not i.filename.endswith(TEXT):
                continue
            if not take(i.file_size):
                return
            yield i.filename, z.read(i, pwd=pwd).decode("utf-8", "replace")
        return
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
        for m in t:
            if not m.isfile():
                continue
            if m.name.endswith(ARCHIVE) and m.size <= MAX_ARCHIVE:
                f = t.extractfile(m)
                if f:
                    yield from nested(m.name, f.read())
                continue
            if m.size > MAX_FILE or not m.name.endswith(TEXT):
                continue
            if not take(m.size):
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


# Signals that are normal alone but tell a story together, in code that runs at install time.
NET = re.compile(r"require\(\s*['\"](node:)?(https?|net|dns|tls|dgram)['\"]\s*\)|from\s+['\"](node:)?(https?|net|dns)['\"]|https?\.(get|request)\s*\(|\bfetch\s*\(|axios|requests\.(get|post|put)|urllib\.request|urlopen|http\.client|socket\.(socket|connect)|net\.(connect|Socket)|dns\.(lookup|resolve)|XMLHttpRequest")
RECON = re.compile(r"os\.(hostname|userInfo|homedir)\s*\(|process\.env\b|os\.environ|os\.getenv|getpass|platform\.node|socket\.gethostname|os\.getlogin|whoami|os\.networkInterfaces")
CATCHER = re.compile(r"oast\.(fun|me|pro|live|site|online)|interact\.sh|burpcollaborator|pipedream\.net|webhook\.site|requestbin\.(com|net|io)|canarytokens\.(com|org)|dnslog\.cn|ceye\.io|\.ngrok(-free)?\.(io|app)", re.I)
HIDDEN = re.compile(r"base64|b64decode|atob\s*\(|zlib\.decompress|marshal|\\x[0-9a-f]{2}", re.I)
SETUP_HOOK = re.compile(r"class\s+\w+\s*\(\s*(install|develop|egg_info|_install|build_py)\s*\)|cmdclass\s*=\s*\{[^}]*['\"](install|develop|egg_info)['\"]")


def _hook_targets(scripts: dict[str, str]) -> set[str]:
    """Files an npm install hook runs, e.g. `node index.js` -> {'index.js'}."""
    out = set()
    for cmd in scripts.values():
        out |= {t.lstrip("./") for t in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|sh|py)", cmd)}
    return out


def _combos(res: Inspection, files: list[tuple[str, str]], hook_files: set[str]) -> None:
    def add(sev: int, label: str, path: str, text: str, m: re.Match | None) -> None:
        line = text.count("\n", 0, m.start()) + 1 if m else 1
        snip = text[max(0, m.start() - 30): m.end() + 30].replace("\n", " ").strip()[:120] if m else ""
        res.findings.append(Finding(sev, label, path.split("/", 1)[-1], line, snip, True))

    for path, text in files:
        if SKIP.search(path) or "node_modules/" in path:
            continue
        base = path.rsplit("/", 1)[-1]
        hooked = any(path.endswith("/" + h) or path == h for h in hook_files)
        install_time = hooked or base in ("setup.py", "install.js", "preinstall.js", "postinstall.js")
        import_time = base == "__init__.py" and path.count("/") <= 3
        if m := CATCHER.search(text):
            add(3, "sends data to a known data-collection service", path, text, m)
        if base == "setup.py" and (hm := SETUP_HOOK.search(text)):
            if NET.search(text) or HIDDEN.search(text):
                add(3, "setup.py replaces the install step with its own code", path, text, hm)
        net, recon = NET.search(text), RECON.search(text)
        cred = RULES[0][2].search(text)
        if cred and net and (install_time or import_time):
            add(3, "reads credentials and sends them out", path, text, cred)
        if install_time and net and recon:
            add(3, "sends machine or user details out during install", path, text, net)
        elif install_time and net:
            add(2, "goes online during install", path, text, net)
        elif import_time and net and recon and HIDDEN.search(text):
            add(3, "hides code that phones home on import", path, text, net)


def agent_text(path: str, text: str) -> list[Finding]:
    """Text in a package that targets the AI agent using it, e.g. an MCP tool description.

    Invisible Tags-block text has no honest use, so it always counts. Plain-sight instructions count
    only when two different kinds appear in one file, which keeps normal docs (".env" in dotenv's
    README) from tripping it.
    """
    out: list[Finding] = []
    short = path.split("/", 1)[-1]
    h = hidden_text(text)
    if h.tags:
        said = (" (hidden text: \"" + h.decoded[0][:80] + "\")") if h.decoded else ""
        out.append(Finding(3, "hides invisible instructions for AI agents" + said, short, h.lines[0] if h.lines else 1, "", False))
    if path.lower().endswith(".md"):  # docs explain things like ".env" freely; only hidden text counts there
        return out
    hits = agent_instructions(text)
    kinds = {label for label, _, _ in hits}
    # In code, an instruction to the agent needs a hiding signal ("don't tell the user", an <IMPORTANT>
    # block) plus one more kind; the hiding is what separates an attack from a docstring.
    hiding = {"tells the agent to hide what it does", "hides an instruction block inside a tool description"}
    if len(kinds) >= 2 and kinds & hiding:
        label, line, snip = hits[0]
        out.append(Finding(3, "tells AI agents to act behind the user's back (" + ", ".join(sorted({l for l, _, _ in hits}))[:120] + ")", short, line, snip, False))
    return out


def analyze(res: Inspection, members) -> Inspection:
    """Scan (path, text) pairs into `res`. Shared by the live agent and the eval."""
    files = list(members)
    manifests = sorted((p for p, _ in files if p.rsplit("/", 1)[-1] == "package.json" and "node_modules/" not in p), key=lambda p: p.count("/"))
    root_manifest = manifests[0] if manifests else None
    for path, text in files:
        res.files_read += 1
        if SKIP.search(path) or "node_modules/" in path:
            continue
        if path == root_manifest:
            try:
                scripts = json.loads(text).get("scripts") or {}
                res.install_scripts = {k: str(v) for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")}
                for cmd in res.install_scripts.values():  # the hook command itself
                    res.findings += scan_text("package.json (install hook)", cmd)
            except (ValueError, AttributeError):
                pass
        res.findings += agent_text(path, text)
        if not path.lower().endswith(".md"):  # docs are read only for agent-directed text
            res.findings += scan_text(path, text)
    hooks = _hook_targets(res.install_scripts)
    _combos(res, files, hooks)
    # A shell script or build config in the archive only matters if an install hook runs it.
    for f in res.findings:
        if f.file.endswith((".sh", ".bat", ".ps1", ".cmd", ".toml", ".cfg", ".txt")) and not any(f.file.endswith(h) for h in hooks):
            f.severity = min(f.severity, 1)
    if res.files_read == 0 and not res.error:
        res.error = "no readable source files in the archive"
    # One line per label is enough for a chat message; keep the worst instance.
    best: dict[str, Finding] = {}
    for f in sorted(res.findings, key=lambda f: (-f.severity, not f.autorun)):
        best.setdefault(f.label, f)
    res.findings = list(best.values())
    return res


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
        return analyze(res, _members(bytes(buf), url))
    except Exception as e:  # report, never crash the agent
        res.error = str(e)[:200]
        return res


# Normal for any installer, so they don't count against a script on their own.
INSTALLER_NORMAL = {"downloads something and runs it", "runs shell commands", "fingerprints the machine", "talks to a raw IP address"}
MAX_SCRIPT = 1024 * 1024


async def read_script(url: str) -> Inspection:
    """Download an install script as text (never run it) and read it like install-time code."""
    res = Inspection("script", url.split("?", 1)[0][-80:])
    if not url.lower().startswith(("https://", "http://")):
        res.error = "only http(s) links can be read"
        return res
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            async with c.stream("GET", url, headers=UA) as r:
                r.raise_for_status()
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_SCRIPT:
                        raise ValueError("script is larger than 1 MB, not reading it")
        text = bytes(buf).decode("utf-8", "replace")
    except Exception as e:
        res.error = str(e)[:160]
        return res
    res.files_read = 1
    res.findings = script_findings(text)
    return res


SENDS = re.compile(r"(curl|wget)\b[^\n]*(-d\b|--data|-F\b|--upload-file|-T\b|--post)|\bnc\s+-?\w*\s*[\w.-]+\s+\d+|/dev/tcp/", re.I)


def script_findings(text: str) -> list[Finding]:
    """What an install script would do if piped to a shell. Downloading and running tools is normal
    for an installer; reading keys, sending data out and hiding instructions are not."""
    out: list[Finding] = []
    for f in scan_text("install.sh", text) + agent_text("install.sh", text):
        if f.label in INSTALLER_NORMAL:
            f.severity = 1
        f.autorun = True  # whatever is in it runs the moment someone pipes it to a shell
        out.append(f)
    if m := CATCHER.search(text):
        out.append(Finding(3, "sends data to a known data-collection service", "install.sh", text.count("\n", 0, m.start()) + 1, "", True))
    cred, send = RULES[0][2].search(text), SENDS.search(text)
    if cred and send:
        out.append(Finding(3, "reads your keys and sends them out", "install.sh", text.count("\n", 0, send.start()) + 1, "", True))
    best: dict[str, Finding] = {}
    for f in sorted(out, key=lambda f: -f.severity):
        best.setdefault(f.label, f)
    return list(best.values())

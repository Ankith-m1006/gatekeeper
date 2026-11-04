"""Live checks against the npm and PyPI registries.

Everything here reads public registry data only. Nothing is installed or executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import httpx

DATA = Path(__file__).resolve().parent / "data"
UA = {"User-Agent": "gatekeeper-flip-the-switch (+https://github.com/Ankith-m1006)"}


@dataclass
class PackageReport:
    ecosystem: str          # "npm" or "pypi"
    name: str
    exists: bool
    created: datetime | None = None
    latest: str | None = None
    versions: int = 0
    maintainers: list[str] = field(default_factory=list)
    downloads: int | None = None          # npm: last week; pypi: last month
    has_install_scripts: bool = False     # npm preinstall/install/postinstall in the latest version
    similar_to: str | None = None         # popular package this name is one typo away from
    repository: str | None = None
    description: str | None = None
    flags: list[str] = field(default_factory=list)

    @property
    def age_days(self) -> int | None:
        if not self.created:
            return None
        return (datetime.now(timezone.utc) - self.created).days

    @property
    def verdict(self) -> str:
        """ghost | danger | suspicious | ok"""
        if not self.exists:
            return "ghost"
        if self.similar_to and (self.age_days or 0) < 365:
            return "danger"
        if self.flags:
            return "suspicious"
        return "ok"


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------- typosquat check ----------------

@lru_cache(maxsize=2)
def popular(ecosystem: str) -> tuple[str, ...]:
    f = DATA / f"popular-{ecosystem}.txt"
    if not f.exists():
        return ()
    return tuple(l.strip().lower() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#"))


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def _edit_distance(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein (adjacent swaps count as one edit), stops early past `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def imitates(new: str, real: str) -> bool:
    """True when `new` is a different name one typo away from `real` (the same test lookalike() uses)."""
    a, b = _norm(new), _norm(real)
    if a == b or len(b) < 4:
        return False
    if a.replace("-", "") == b.replace("-", ""):
        return True
    d = _edit_distance(a, b)
    return d == 1 or (d == 2 and len(b) >= 8)


def lookalike(ecosystem: str, name: str) -> str | None:
    """Return the popular package this name imitates, if any (and it is not that package)."""
    n = _norm(name)
    top = popular(ecosystem)
    if not top or n in top:
        return None
    bare = n.replace("-", "")
    for p in top:
        if len(p) < 4:
            continue
        if bare == p.replace("-", ""):                      # request vs re-quest, python-dateutil vs pythondateutil
            return p
        d = _edit_distance(n, p)
        if d == 1 or (d == 2 and len(p) >= 8):
            return p
    return None


# ---------------- registries ----------------

async def check_npm(client: httpx.AsyncClient, name: str) -> PackageReport:
    r = await client.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}", headers=UA)
    if r.status_code == 404:
        return PackageReport("npm", name, exists=False, similar_to=lookalike("npm", name))
    r.raise_for_status()
    d = r.json()
    latest = (d.get("dist-tags") or {}).get("latest")
    v = (d.get("versions") or {}).get(latest) or {}
    scripts = v.get("scripts") or {}
    rep = PackageReport(
        "npm", name, exists=True,
        created=_parse_time((d.get("time") or {}).get("created")),
        latest=latest,
        versions=len(d.get("versions") or {}),
        maintainers=[m.get("name", "") for m in d.get("maintainers") or []],
        has_install_scripts=any(k in scripts for k in ("preinstall", "install", "postinstall")),
        similar_to=lookalike("npm", name),
        repository=(v.get("repository") or {}).get("url") if isinstance(v.get("repository"), dict) else v.get("repository"),
        description=d.get("description"),
    )
    try:
        dl = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{name}", headers=UA)
        if dl.status_code == 200:
            rep.downloads = dl.json().get("downloads")
    except httpx.HTTPError:
        pass
    _flag(rep)
    return rep


async def check_pypi(client: httpx.AsyncClient, name: str) -> PackageReport:
    r = await client.get(f"https://pypi.org/pypi/{name}/json", headers=UA)
    if r.status_code == 404:
        return PackageReport("pypi", name, exists=False, similar_to=lookalike("pypi", name))
    r.raise_for_status()
    d = r.json()
    info = d.get("info") or {}
    releases = d.get("releases") or {}
    uploads = [_parse_time(f.get("upload_time_iso_8601")) for files in releases.values() for f in files]
    uploads = [u for u in uploads if u]
    urls = info.get("project_urls") or {}
    rep = PackageReport(
        "pypi", name, exists=True,
        created=min(uploads) if uploads else None,
        latest=info.get("version"),
        versions=len(releases),
        maintainers=[x for x in (info.get("author"), info.get("maintainer")) if x],
        similar_to=lookalike("pypi", name),
        repository=urls.get("Source") or urls.get("Repository") or urls.get("Homepage") or info.get("home_page"),
        description=info.get("summary"),
    )
    if (rep.age_days or 9999) < 90:
        try:
            dl = await client.get(f"https://pypistats.org/api/packages/{name.lower()}/recent", headers=UA)
            if dl.status_code == 200:
                rep.downloads = (dl.json().get("data") or {}).get("last_month")
        except httpx.HTTPError:
            pass
    _flag(rep)
    return rep


def _flag(rep: PackageReport) -> None:
    age = rep.age_days
    if age is not None and age < 30:
        rep.flags.append(f"published only {age} days ago")
    if rep.versions <= 1:
        rep.flags.append("only one version ever")
    if rep.has_install_scripts:
        rep.flags.append("runs a script on install")
    if rep.downloads is not None and rep.downloads < 100 and rep.ecosystem == "npm":
        rep.flags.append(f"{rep.downloads} downloads last week")
    if not rep.repository:
        rep.flags.append("no source repository linked")
    if rep.similar_to:
        rep.flags.append(f"one typo away from `{rep.similar_to}`")


async def check(ecosystem: str, name: str) -> PackageReport:
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
        return await (check_npm(c, name) if ecosystem == "npm" else check_pypi(c, name))

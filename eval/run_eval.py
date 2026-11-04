"""Measure the crew on real malware and on the most popular real packages.

Malicious side: Datadog's open dataset of packages removed from npm and PyPI after human triage
(github.com/DataDog/malicious-software-packages-dataset, Apache-2.0). Each sample is an encrypted
zip; it is read in memory with Python's zipfile and never extracted or executed.

Benign side: the most downloaded npm and PyPI packages, fetched live like the agent does.

Run on a throwaway machine (we use the Switch VM): python -m eval.run_eval
"""
from __future__ import annotations

import asyncio
import collections
import json
import random
import sys
import time
from pathlib import Path

import httpx

from gatekeeper.inspect_pkg import Inspection, _members, analyze, inspect
from gatekeeper.registry import DATA, lookalike

REPO = "DataDog/malicious-software-packages-dataset"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/"
OUT = Path(__file__).resolve().parent
N_BAD = int(sys.argv[1]) if len(sys.argv) > 1 else 200      # per ecosystem
N_GOOD = int(sys.argv[2]) if len(sys.argv) > 2 else 500     # per ecosystem
GOOD_FROM = int(sys.argv[3]) if len(sys.argv) > 3 else 0     # 0 = tuning batch, 500 = held-out batch
ONLY = sys.argv[4] if len(sys.argv) > 4 else "all"           # all | benign
SEM = asyncio.Semaphore(12)


def tree(c: httpx.Client, eco: str) -> list[str]:
    sha = next(x["sha"] for x in c.get(f"https://api.github.com/repos/{REPO}/contents/samples").json() if x["name"] == eco)
    t = c.get(f"https://api.github.com/repos/{REPO}/git/trees/{sha}?recursive=1").json()
    return [f"samples/{eco}/{x['path']}" for x in t["tree"] if x["path"].startswith("malicious_intent/") and x["path"].endswith(".zip")]


def pick(paths: list[str], n: int) -> list[str]:
    """One sample per package name, newest version, random but repeatable."""
    by_name: dict[str, str] = {}
    for p in sorted(paths):
        by_name[p.split("/")[3]] = p
    names = sorted(by_name)
    random.Random(7).shuffle(names)
    return [by_name[k] for k in names[:n]]


async def bad_one(c: httpx.AsyncClient, eco: str, path: str) -> dict:
    name = path.split("/")[3]
    res = Inspection(eco, name)
    async with SEM:
        try:
            r = await c.get(RAW + path)
            r.raise_for_status()
            analyze(res, _members(r.content, path, pwd=b"infected"))
        except Exception as e:
            res.error = str(e)[:160]
    return row(res, "malicious", path)


async def good_one(eco: str, name: str) -> dict:
    async with SEM:
        res = await inspect(eco, name)
    return row(res, "benign", None)


def row(res: Inspection, truth: str, path: str | None) -> dict:
    return {
        "ecosystem": res.ecosystem, "name": res.name, "truth": truth, "sample": path,
        "verdict": res.verdict, "score": res.score, "files": res.files_read, "error": res.error,
        "install_scripts": bool(res.install_scripts),
        "labels": sorted({f.label for f in res.findings}),
        "lookalike": lookalike(res.ecosystem, res.name),
    }


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def report(rows: list[dict]) -> str:
    L = [f"# Gatekeeper eval ({time.strftime('%d %b %Y')})", ""]
    for eco in ("npm", "pypi"):
        bad = [r for r in rows if r["ecosystem"] == eco and r["truth"] == "malicious" and not r["error"]]
        good = [r for r in rows if r["ecosystem"] == eco and r["truth"] == "benign" and not r["error"]]
        if not bad and not good:
            continue
        caught = sum(r["verdict"] == "malicious-looking" for r in bad)
        flagged = sum(r["verdict"] in ("malicious-looking", "risky") for r in bad)
        fp_block = sum(r["verdict"] == "malicious-looking" for r in good)
        fp_any = sum(r["verdict"] in ("malicious-looking", "risky") for r in good)
        L += [f"## {eco}",
              f"- Real malware read: {len(bad)}. Called **malicious-looking**: {caught} ({pct(caught, len(bad))}). Flagged at all (risky or worse): {flagged} ({pct(flagged, len(bad))}).",
              f"- Popular real packages read: {len(good)}. Wrongly called malicious-looking: {fp_block} ({pct(fp_block, len(good))}). Asked for a human look (risky): {fp_any - fp_block} ({pct(fp_any - fp_block, len(good))}).",
              f"- Malware names one typo from a top-3000 package: {sum(1 for r in bad if r['lookalike'])} of {len(bad)}.", ""]
        hits = collections.Counter(l for r in bad for l in r["labels"])
        L.append("What the malware did, as Inspector saw it: " + "; ".join(f"{k} ({v})" for k, v in hits.most_common(8)))
        fps = [f"{r['name']} ({', '.join(r['labels'][:2])})" for r in good if r["verdict"] == "malicious-looking"]
        if fps:
            L.append("False alarms to study: " + ", ".join(fps[:15]))
        L.append("")
    errs = sum(1 for r in rows if r["error"])
    L.append(f"Unreadable (download or archive errors, left out of the numbers above): {errs}.")
    return "\n".join(L)


async def main() -> None:
    with httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": "gatekeeper-eval"}) as c:
        bad_paths = {eco: pick(tree(c, eco), N_BAD) for eco in ("npm", "pypi")}
    good = {eco: [l.strip() for l in (DATA / f"popular-{eco}.txt").read_text().splitlines() if l.strip() and not l.startswith("#")][GOOD_FROM:GOOD_FROM + N_GOOD] for eco in ("npm", "pypi")}
    async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers={"User-Agent": "gatekeeper-eval"}) as c:
        jobs = [] if ONLY == "benign" else [bad_one(c, eco, p) for eco, ps in bad_paths.items() for p in ps]
        jobs += [good_one(eco, n) for eco, ns in good.items() for n in ns]
        rows = []
        for i, fut in enumerate(asyncio.as_completed(jobs), 1):
            rows.append(await fut)
            if i % 100 == 0:
                print(f"{i}/{len(jobs)}", flush=True)
    tag = f"-{ONLY}-{GOOD_FROM}" if (ONLY != "all" or GOOD_FROM) else ""
    (OUT / f"results{tag}.json").write_text(json.dumps(rows, indent=1))
    md = report(rows)
    (OUT / f"RESULTS{tag}.md").write_text(md)
    print(md)


if __name__ == "__main__":
    asyncio.run(main())

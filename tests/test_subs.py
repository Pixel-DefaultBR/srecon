from pathlib import Path

from srecon import scope
from srecon.commands import subs as subs_cmd


def test_clean_host():
    assert subs_cmd._clean(" A.Example.com. ") == "a.example.com"
    assert subs_cmd._clean("bad host") is None
    assert subs_cmd._clean("evil,x.com") is None
    assert subs_cmd._clean("") is None


def test_enumerate_parsing(monkeypatch):
    monkeypatch.setattr(subs_cmd, "resolve_bin", lambda n: "/usr/bin/subfinder")
    monkeypatch.setattr(subs_cmd, "_run",
                        lambda cmd, timeout, input_text=None:
                        (0, "a.example.com\nB.example.com\n\nbad host\na.example.com\n"))
    subs, rc = subs_cmd.enumerate_subdomains("example.com")
    assert rc == 0
    assert subs == ["a.example.com", "b.example.com"]     # dedup + lower + descarta 'bad host'


def test_resolve_parsing(monkeypatch):
    monkeypatch.setattr(subs_cmd, "resolve_bin", lambda n: "/usr/bin/dnsx")
    out = ('{"host":"a.example.com","a":["1.2.3.4","1.2.3.5"]}\n'
           'nao-json\n'
           '{"host":"c.example.com","a":["9.9.9.9"]}\n')
    monkeypatch.setattr(subs_cmd, "_run",
                        lambda cmd, timeout, input_text=None: (0, out))
    resolved, rc = subs_cmd.resolve_hosts(["a.example.com", "c.example.com"])
    assert rc == 0
    assert resolved == [("a.example.com", ["1.2.3.4", "1.2.3.5"]),
                        ("c.example.com", ["9.9.9.9"])]


def test_run_scope_annotation(monkeypatch):
    monkeypatch.setattr(subs_cmd, "enumerate_subdomains",
                        lambda d, all_sources=True, timeout=300, extra=None:
                        (["a.example.com", "b.other.com"], 0))
    monkeypatch.setattr(subs_cmd, "resolve_hosts",
                        lambda hosts, timeout=120:
                        ([("a.example.com", ["1.1.1.1"]),
                          ("b.other.com", ["2.2.2.2"]),
                          ("example.com", ["3.3.3.3"])], 0))
    entries = [scope.parse_scope_text("*.example.com", Path("t.txt"))]
    res = subs_cmd.run("example.com", entries)
    assert "example.com" in res.subdomains          # o próprio domínio entra
    assert set(res.in_scope) == {"a.example.com", "example.com"}
    assert res.out_scope == ["b.other.com"]
    assert res.live_hosts == ["a.example.com", "b.other.com", "example.com"]

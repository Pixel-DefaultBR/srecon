from pathlib import Path

from srecon.commands import pipeline as pl


def test_gather_from_file_cleans_and_dedups(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("a.example.com\n# comentário\nb.example.com\na.example.com\n"
                 "evil host\n\n", encoding="utf-8")
    hosts = pl.gather_targets(None, None, None, None, 50, from_file=f)
    assert hosts == ["a.example.com", "b.example.com"]   # dedup, sem comentário/malformado


def test_gather_from_file_missing_raises(tmp_path):
    try:
        pl.gather_targets(None, None, None, None, 50, from_file=tmp_path / "nope.txt")
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass


def test_gather_from_subs(monkeypatch):
    monkeypatch.setattr(pl.subs_cmd, "enumerate_subdomains",
                        lambda d, timeout=300: (["a.example.com", "b.example.com"], 0))
    monkeypatch.setattr(pl.subs_cmd, "resolve_hosts",
                        lambda hosts, timeout=120:
                        ([("a.example.com", ["1.1.1.1"])], 0))   # só 'a' resolve
    hosts = pl.gather_targets(None, None, None, None, 50, from_subs="example.com")
    assert hosts == ["a.example.com"]                    # usa os vivos do dnsx


def test_gather_from_subs_fallback_when_no_resolve(monkeypatch):
    monkeypatch.setattr(pl.subs_cmd, "enumerate_subdomains",
                        lambda d, timeout=300: (["a.example.com"], 0))
    monkeypatch.setattr(pl.subs_cmd, "resolve_hosts",
                        lambda hosts, timeout=120: ([], 0))       # nada resolve
    hosts = pl.gather_targets(None, None, None, None, 50, from_subs="example.com")
    assert set(hosts) == {"a.example.com", "example.com"}  # cai pros subs crus


def test_decide_scope(tmp_path):
    (tmp_path / "s.txt").write_text("*.example.com", encoding="utf-8")
    dec = pl.decide_scope(["a.example.com", "b.other.com"], tmp_path, None, override=False)
    assert dec.in_scope == ["a.example.com"]
    assert dec.out_scope == ["b.other.com"]
    assert any("s.txt" in s for s in dec.sources)


def test_decide_scope_override(tmp_path):
    dec = pl.decide_scope(["x.evil.com"], tmp_path, None, override=True)
    assert dec.in_scope == ["x.evil.com"]
    assert "OVERRIDE (--i-am-authorized)" in dec.source

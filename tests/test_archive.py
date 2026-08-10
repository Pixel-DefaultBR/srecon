from pathlib import Path

from srecon import archive, scope


def _scope(text="*.example.com"):
    return [scope.parse_scope_text(text, Path("s.txt"))]


def test_wayback_cdx_url_domain_and_host():
    u = archive.wayback_cdx_url("example.com", include_subs=True, limit=100)
    assert "web.archive.org/cdx/search/cdx" in u
    assert "matchType=domain" in u
    assert "fl=original" in u and "collapse=urlkey" in u
    assert "limit=100" in u
    u2 = archive.wayback_cdx_url("app.example.com", include_subs=False)
    assert "matchType=host" in u2
    assert "limit=" not in u2                      # sem limit quando None


def test_wayback_cdx_url_status_filter():
    u = archive.wayback_cdx_url("example.com", status_ok_only=True)
    assert "statuscode%3A200" in u or "statuscode:200" in u


def test_parse_cdx_text_normalizes_and_drops_junk():
    text = (
        "https://a.example.com/x?id=1\n"
        "http://b.example.com/login\n"
        "ftp://c.example.com/nope\n"          # esquema não-http -> descarta
        "not a url\n"                          # lixo -> descarta
        "   \n"                                # vazio -> descarta
        "https://a.example.com/x?id=1\n"       # duplicata (dedup fica no collect)
    )
    urls = archive.parse_cdx_text(text)
    assert "https://a.example.com/x?id=1" in urls
    assert "http://b.example.com/login" in urls
    assert all(u.startswith(("http://", "https://")) for u in urls)
    assert not any("ftp://" in u for u in urls)


def test_normalize_url_rejects_whitespace_and_bad_host():
    assert archive.normalize_url("https://a.example.com/x") == "https://a.example.com/x"
    assert archive.normalize_url("https://a.example.com/x y") is None
    assert archive.normalize_url("https:///nohost") is None
    assert archive.normalize_url("javascript:alert(1)") is None


def test_dedup_urls_sorted_unique():
    got = archive.dedup_urls(["https://b/x", "https://a/y", "https://b/x", ""])
    assert got == ["https://a/y", "https://b/x"]


def test_build_param_inventory_counts_and_examples():
    urls = [
        "https://a.example.com/p?id=1&next=/home",
        "https://a.example.com/q?id=2",
        "https://a.example.com/r?redirect=http://x",
    ]
    inv = archive.build_param_inventory(urls)
    assert set(inv) == {"id", "next", "redirect"}
    assert inv["id"].count == 2                    # aparece em 2 URLs distintas
    assert inv["next"].count == 1
    assert inv["id"].example.startswith("https://a.example.com/p")
    assert "1" in inv["id"].values


def test_param_inventory_dedups_repeated_name_in_same_url():
    inv = archive.build_param_inventory(["https://a/x?id=1&id=2"])
    assert inv["id"].count == 1                    # mesmo nome 2x na MESMA URL = 1


def test_partition_scope_by_host():
    urls = [
        "https://api.example.com/v1/x",
        "https://evil.com/x",
        "https://deep.sub.example.com/y",
    ]
    ins, out = archive.partition_scope(urls, _scope())
    assert "https://api.example.com/v1/x" in ins
    assert "https://deep.sub.example.com/y" in ins
    assert "https://evil.com/x" in out


def test_partition_scope_respects_deny():
    # host negado NÃO entra em in-scope mesmo sob wildcard (integra com Fase 0)
    sc = _scope("*.example.com\n# out of scope:\nadmin.example.com")
    ins, out = archive.partition_scope(
        ["https://admin.example.com/x", "https://api.example.com/y"], sc)
    assert "https://api.example.com/y" in ins
    assert "https://admin.example.com/x" in out


def test_collect_orchestrates_and_classifies(monkeypatch):
    # sem rede: injeta URLs em fetch_wayback e desliga gau
    fake = [
        "https://a.example.com/api/v1/users?id=1",
        "https://a.example.com/static/app.js",
        "https://a.example.com/backup.zip",
        "https://evil.com/leak?id=9",
    ]
    monkeypatch.setattr(archive, "fetch_wayback", lambda *a, **k: list(fake))
    res = archive.collect("example.com", _scope(), use_wayback=True, use_gau=False)
    assert res.sources["wayback"] == 4
    assert len(res.urls) == 4
    assert "https://evil.com/leak?id=9" in res.out_scope
    assert "https://a.example.com/api/v1/users?id=1" in res.in_scope
    assert any(u.endswith("backup.zip") for u in res.interesting)
    assert any("/api/" in u for u in res.api)
    assert "id" in res.params


def test_collect_degrades_when_wayback_fails(monkeypatch):
    def boom(*a, **k):
        raise archive.ArchiveError("HTTP 503")
    monkeypatch.setattr(archive, "fetch_wayback", boom)
    res = archive.collect("example.com", _scope(), use_wayback=True, use_gau=False)
    assert res.urls == []
    assert res.errors and res.errors[0][0] == "wayback"


def test_collect_invalid_domain():
    import pytest
    with pytest.raises(ValueError):
        archive.collect("   ", _scope())


def test_write_urls_files(tmp_path, monkeypatch):
    fake = ["https://a.example.com/x?q=1", "https://a.example.com/api/v1/z"]
    monkeypatch.setattr(archive, "fetch_wayback", lambda *a, **k: list(fake))
    res = archive.collect("example.com", _scope(), use_wayback=True, use_gau=False)
    from srecon import report
    report.write_urls_files(res, tmp_path)
    assert (tmp_path / "urls-all.txt").read_text().strip().splitlines()
    assert (tmp_path / "params.txt").read_text().splitlines() == ["q"]
    assert "api/v1/z" in (tmp_path / "api.txt").read_text()
    assert (tmp_path / "urls.md").exists()


def test_param_inventory_drops_junk_names():
    # nomes-lixo (símbolos, encoding quebrado) NÃO entram na wordlist
    urls = [
        "https://a/x?id=1&redirect=/y",   # bons
        "http://a/$1$2.php?%242=%245",    # '$2' etc -> lixo
        "https://a/z?,-=1&@_~=2",         # símbolos -> lixo
    ]
    inv = archive.build_param_inventory(urls)
    assert set(inv) == {"id", "redirect"}

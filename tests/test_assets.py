import base64
import json
from pathlib import Path

from srecon import assets, scope


def _scope(text="*.example.com"):
    return [scope.parse_scope_text(text, Path("s.txt"))]


def test_mmh3_known_vectors():
    # vetores canônicos do MurmurHash3 x86_32 (assinado, como o mmh3.hash do Shodan)
    assert assets.mmh3_32(b"") == 0
    assert assets.mmh3_32(b"foo") == -156908512
    assert assets.mmh3_32(b"hello") == 613153351


def test_favicon_hash_uses_base64_encodebytes_recipe():
    data = b"\x89PNG\r\n\x1a\n" + b"fake-favicon-bytes" * 10
    assert assets.favicon_hash(data) == assets.mmh3_32(base64.encodebytes(data))


def test_crtsh_url():
    u = assets.crtsh_url("example.com")
    assert "crt.sh" in u and "output=json" in u
    assert "example.com" in u


def test_parse_crtsh_json_extracts_and_cleans_hosts():
    raw = json.dumps([
        {"name_value": "a.example.com\n*.b.example.com", "common_name": "a.example.com"},
        {"name_value": "c.example.com"},
        {"name_value": "bad host with space"},         # inválido -> descarta
        {"common_name": "*.d.example.com"},
    ])
    hosts = assets.parse_crtsh_json(raw)
    assert "a.example.com" in hosts
    assert "b.example.com" in hosts                      # wildcard normalizado
    assert "c.example.com" in hosts
    assert "d.example.com" in hosts
    assert not any(" " in h for h in hosts)


def test_parse_crtsh_json_bad_input():
    assert assets.parse_crtsh_json("not json") == set()
    assert assets.parse_crtsh_json(json.dumps({"not": "a list"})) == set()


def test_parse_bgpview_ip():
    raw = json.dumps({
        "status": "ok",
        "data": {"prefixes": [
            {"prefix": "203.0.113.0/24",
             "asn": {"asn": 64500, "name": "ACME", "description": "ACME Corp", "country_code": "BR"}},
        ]},
    })
    info = assets.parse_bgpview_ip(raw, "203.0.113.7")
    assert info.asn == 64500
    assert info.prefix == "203.0.113.0/24"
    assert info.org == "ACME Corp"
    assert info.country == "BR"


def test_parse_bgpview_ip_error_status():
    assert assets.parse_bgpview_ip(json.dumps({"status": "error"}), "1.2.3.4") is None
    assert assets.parse_bgpview_ip("garbage", "1.2.3.4") is None


def test_partition_scope_respects_deny():
    sc = _scope("*.example.com\n# out of scope:\nadmin.example.com")
    ins, out = assets.partition_scope(
        ["api.example.com", "admin.example.com", "evil.com"], sc)
    assert ins == ["api.example.com"]
    assert "admin.example.com" in out and "evil.com" in out


def test_collect_ct_and_partition(monkeypatch):
    monkeypatch.setattr(assets, "fetch_crtsh",
                        lambda *a, **k: {"api.example.com", "admin.example.com", "evil.com"})
    res = assets.collect("example.com", _scope(), do_asn=False)
    assert set(res.ct_hosts) == {"admin.example.com", "api.example.com", "evil.com"}
    assert "api.example.com" in res.in_scope
    assert "evil.com" in res.out_scope


def test_collect_degrades_when_crtsh_fails(monkeypatch):
    def boom(*a, **k):
        raise assets.AssetsError("HTTP 502")
    monkeypatch.setattr(assets, "fetch_crtsh", boom)
    res = assets.collect("example.com", _scope(), do_asn=False)
    assert res.ct_hosts == []
    assert res.errors and res.errors[0][0] == "crt.sh"


def test_collect_invalid_domain():
    import pytest
    with pytest.raises(ValueError):
        assets.collect("  ", _scope())


class _FakeClient:
    def __init__(self, total=42, ips=("1.1.1.1", "2.2.2.2")):
        self._total = total
        self._ips = ips

    def count(self, query, facets=None):
        return {"total": self._total}

    def search(self, query, limit=100):
        class M:
            def __init__(self, ip):
                self.ip = ip
        class R:
            pass
        r = R()
        r.matches = [M(ip) for ip in self._ips]
        return r


def test_shodan_favicon_pivot_count_and_hosts():
    out = assets.shodan_favicon_pivot(_FakeClient(total=42), -156908512)
    assert out["query"] == "http.favicon.hash:-156908512"
    assert out["shodan_count"] == 42
    assert out["shodan_hosts"] == ["1.1.1.1", "2.2.2.2"]


def test_shodan_favicon_pivot_zero_count_skips_search():
    out = assets.shodan_favicon_pivot(_FakeClient(total=0), 123)
    assert out["shodan_count"] == 0
    assert "shodan_hosts" not in out


def test_write_assets_files(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, "fetch_crtsh", lambda *a, **k: {"api.example.com", "evil.com"})
    res = assets.collect("example.com", _scope(), do_asn=False)
    from srecon import report
    report.write_assets_files(res, tmp_path)
    assert "api.example.com" in (tmp_path / "ct-hosts.txt").read_text()
    assert (tmp_path / "in-scope.txt").read_text().strip() == "api.example.com"
    assert (tmp_path / "assets.md").exists()


def test_fetch_crtsh_retries_transient_5xx(monkeypatch):
    # 502 nas 2 primeiras, sucesso na 3ª -> retorna sem propagar erro
    calls = {"n": 0}

    def flaky(url, timeout=30.0):
        calls["n"] += 1
        if calls["n"] < 3:
            raise assets.AssetsError("HTTP 502 em crt.sh")
        return __import__("json").dumps([{"name_value": "a.example.com"}])

    monkeypatch.setattr(assets, "_get", flaky)
    monkeypatch.setattr(assets, "_sleep", lambda *_: None)   # não dorme no teste
    hosts = assets.fetch_crtsh("example.com", retries=2)
    assert hosts == {"a.example.com"}
    assert calls["n"] == 3


def test_fetch_crtsh_gives_up_after_retries(monkeypatch):
    def always(url, timeout=30.0):
        raise assets.AssetsError("HTTP 502 em crt.sh")
    monkeypatch.setattr(assets, "_get", always)
    monkeypatch.setattr(assets, "_sleep", lambda *_: None)
    import pytest
    with pytest.raises(assets.AssetsError):
        assets.fetch_crtsh("example.com", retries=2)

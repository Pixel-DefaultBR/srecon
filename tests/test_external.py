import json

from srecon import external


def test_candidates_prefer_kali_then_canonical():
    assert external._candidates("httpx") == ["httpx-toolkit", "httpx"]
    assert external._candidates("testssl") == ["testssl", "testssl.sh"]
    assert external._candidates("katana") == ["katana"]


def test_resolve_bin_falls_back_to_canonical(monkeypatch):
    monkeypatch.setattr(external, "_EXTRA_BIN_DIRS", [])
    # só o nome canônico 'httpx' existe (cenário go install)
    monkeypatch.setattr(external.shutil, "which",
                        lambda n: "/usr/bin/httpx" if n == "httpx" else None)
    assert external.resolve_bin("httpx") == "/usr/bin/httpx"


def test_resolve_bin_prefers_kali_name(monkeypatch):
    monkeypatch.setattr(external, "_EXTRA_BIN_DIRS", [])
    monkeypatch.setattr(external.shutil, "which",
                        lambda n: f"/usr/bin/{n}")   # tudo existe
    assert external.resolve_bin("httpx") == "/usr/bin/httpx-toolkit"   # Kali primeiro


def test_parse_httpx_urls(tmp_path):
    jf = tmp_path / "httpx.jsonl"
    jf.write_text('{"url":"https://a.com/x"}\nlixo\n{"input":"https://b.com"}\n',
                  encoding="utf-8")
    assert external.parse_httpx_urls(jf) == ["https://a.com/x", "https://b.com"]
    assert external.parse_httpx_urls(tmp_path / "nope.jsonl") == []


def test_parse_httpx_records_and_tech_summary(tmp_path):
    jf = tmp_path / "httpx.jsonl"
    jf.write_text(
        '{"url":"http://a/","status_code":200,"title":"A","webserver":"nginx",'
        '"tech":["Nginx","PHP"],"a":["1.2.3.4"],"cdn_name":null}\n'
        'ruído-não-json\n'
        '{"url":"http://b/","status_code":403,"tech":["Nginx"]}\n',
        encoding="utf-8")
    recs = external.parse_httpx_records(jf)
    assert len(recs) == 2
    assert recs[0]["tech"] == ["Nginx", "PHP"] and recs[0]["webserver"] == "nginx"
    assert recs[0]["ips"] == ["1.2.3.4"]
    summ = external.tech_summary(recs)
    assert summ[0] == ("Nginx", 2)          # tecnologia mais comum primeiro
    assert ("PHP", 1) in summ

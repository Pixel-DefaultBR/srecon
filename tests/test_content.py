from pathlib import Path

from srecon import content


def test_default_wordlist_env_override(tmp_path, monkeypatch):
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\n", encoding="utf-8")
    monkeypatch.setenv("SRECON_WORDLIST", str(wl))
    assert content.default_wordlist() == str(wl)


def test_interesting_files_curated():
    for f in (".git/HEAD", ".env", "web.config", "backup.sql", "actuator/env"):
        assert f in content.INTERESTING_FILES, f
    assert len(content.INTERESTING_FILES) > 30


def test_build_ffuf_cmd():
    cmd = content.build_ffuf_cmd("/usr/bin/ffuf", "http://x/", "/wl.txt",
                                 Path("/o.json"), extensions=".bak,.zip")
    s = " ".join(cmd)
    assert "http://x/FUZZ" in s          # sem barra dupla
    assert "/wl.txt:FUZZ" in s
    assert "-of json" in s
    assert "-e .bak,.zip" in s
    assert "-ac" in cmd                  # anti falso-positivo


def test_parse_ffuf_json_sorted(tmp_path):
    j = tmp_path / "o.json"
    j.write_text('{"results":['
                 '{"input":{"FUZZ":"secret"},"url":"http://x/secret","status":403,"length":5},'
                 '{"input":{"FUZZ":"admin"},"url":"http://x/admin","status":200,"length":10,"words":2,"lines":1}'
                 ']}', encoding="utf-8")
    hits = content.parse_ffuf_json(j)
    assert len(hits) == 2
    assert hits[0]["status"] == 200 and hits[0]["input"] == "admin"   # ordenado por status
    assert content.parse_ffuf_json(tmp_path / "nope.json") == []


def test_drop_wildcard_waf_noise():
    # 200 hits 403/4545 (WAF uniforme) + 2 achados reais -> descarta o cluster
    waf = [{"url": f"http://x/{i}", "status": 403, "length": 4545} for i in range(200)]
    real = [{"url": "http://x/admin", "status": 200, "length": 812},
            {"url": "http://x/login", "status": 401, "length": 99}]
    kept, info = content.drop_wildcard(waf + real)
    assert info["status"] == 403 and info["length"] == 4545 and info["dropped"] == 200
    assert info["fraction"] >= 0.85
    assert {h["url"] for h in kept} == {"http://x/admin", "http://x/login"}


def test_drop_wildcard_leaves_varied_results():
    # resultados variados (sem cluster dominante) não são tocados
    hits = [{"url": f"http://x/{i}", "status": 200, "length": 100 + i} for i in range(40)]
    kept, info = content.drop_wildcard(hits)
    assert info is None and kept == hits


def test_drop_wildcard_ignores_small_sets():
    # poucos hits (< min_count) nunca viram 'wildcard', mesmo idênticos
    hits = [{"url": f"http://x/{i}", "status": 403, "length": 10} for i in range(5)]
    kept, info = content.drop_wildcard(hits)
    assert info is None and kept == hits

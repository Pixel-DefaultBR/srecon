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

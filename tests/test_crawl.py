import json
import os
import stat
from pathlib import Path

from srecon import scope
from srecon.commands import crawl


def test_extract_host_and_seeds():
    assert crawl.extract_host("https://a.example.com:8443/p?x=1") == "a.example.com"
    assert crawl.extract_host("http://user:pw@h.com/p") == "h.com"
    assert crawl.extract_host("[2001:db8::1]:443") == "2001:db8::1"
    # regressão de campo: URL com IP:porta/path -> IP puro (não pode ir p/ DNS/report como URL)
    assert crawl.extract_host("http://177.91.240.182:8080/v1r1/login/") == "177.91.240.182"
    assert crawl.build_seeds("example.com") == "https://example.com,http://example.com"
    assert crawl.build_seeds("https://example.com/") == "https://example.com/"


import re as _re


def test_derive_field_scope_from_wildcard_scope():
    e = scope.parse_scope_text("*.example.com", Path("s.txt"))
    hit = scope.match("www.example.com", [e])
    rx = crawl.derive_field_scope("www.example.com", hit)
    pat = _re.compile(rx)
    # casa hosts autorizados (host e subdomínios); NÃO casa irmão fora de escopo nem lookalike
    assert pat.search("www.example.com")
    assert pat.search("example.com")
    assert pat.search("deep.api.example.com")
    assert not pat.search("evilexample.com")      # sem o ponto -> não é subdomínio
    assert not pat.search("example.com.evil.net")


def test_derive_field_scope_ip_is_exact_host():
    e = scope.parse_scope_text("198.51.100.0/24", Path("s.txt"))
    hit = scope.match("198.51.100.7", [e])
    rx = crawl.derive_field_scope("198.51.100.7", hit)
    pat = _re.compile(rx)
    assert pat.search("198.51.100.7")
    assert not pat.search("198.51.100.70")        # host exato, não prefixo


def test_derive_field_scope_override_locks_to_target():
    # --i-am-authorized sem hit: trava no host alvo, não vira 'rdn' promíscuo
    rx = crawl.derive_field_scope("app.target.com", None)
    pat = _re.compile(rx)
    assert pat.search("app.target.com")
    assert not pat.search("other.target.com")


def test_build_katana_args_auto_scope_and_dr_default():
    e = scope.parse_scope_text("*.example.com", Path("s.txt"))
    hit = scope.match("www.example.com", [e])
    opt = crawl.CrawlOptions(field_scope=crawl.derive_field_scope("www.example.com", hit))
    args = crawl.build_katana_args("katana", "https://www.example.com", Path("/tmp/x"), opt)
    # -dr presente por default (não segue redirect p/ host fora de escopo)
    assert "-dr" in args
    # -fs recebe o regex derivado, não a keyword 'rdn'
    fs_val = args[args.index("-fs") + 1]
    assert "example" in fs_val and fs_val != "rdn"


def test_build_katana_args_follow_redirects_drops_dr():
    opt = crawl.CrawlOptions(disable_redirects=False)
    args = crawl.build_katana_args("katana", "https://x", Path("/tmp/x"), opt)
    assert "-dr" not in args


def test_derive_out_scope_from_deny():
    e = scope.parse_scope_text("*.example.com\n# out of scope:\nadmin.example.com", Path("s.txt"))
    cos = crawl.derive_out_scope([e])
    assert cos and "admin" in cos
    opt = crawl.CrawlOptions(crawl_out_scope=cos)
    args = crawl.build_katana_args("katana", "https://x", Path("/tmp/x"), opt)
    assert "-cos" in args and args[args.index("-cos") + 1] == cos


def test_derive_out_scope_empty_when_no_deny():
    e = scope.parse_scope_text("*.example.com", Path("s.txt"))
    assert crawl.derive_out_scope([e]) == ""


def test_redact_args_hides_header_and_proxy_creds():
    args = ["katana", "-u", "x", "-H", "Cookie: s=secret",
            "-proxy", "http://user:pw@127.0.0.1:8080"]
    red = crawl.redact_args(args)
    assert "Cookie: s=secret" not in red
    assert "<redacted>" in red
    assert "user:pw" not in " ".join(red)
    assert "127.0.0.1:8080" in " ".join(red)


def test_strip_userinfo():
    assert crawl.strip_userinfo("https://user:pw@app.example.com/x") == "https://app.example.com/x"
    assert crawl.strip_userinfo("http://u@h.com") == "http://h.com"
    assert crawl.strip_userinfo("app.example.com/x") == "app.example.com/x"
    # '@' no PATH (não na autoridade) é preservado
    assert crawl.strip_userinfo("https://app.example.com/p@th") == "https://app.example.com/p@th"


def test_redact_args_strips_userinfo_in_seed():
    args = ["katana", "-u", "https://user:pw@app.example.com,http://user:pw@app.example.com"]
    joined = " ".join(crawl.redact_args(args))
    assert "user:pw" not in joined
    assert "app.example.com" in joined


def test_secrets_written_0600(tmp_path):
    art = crawl.CrawlArtifacts()
    art.secrets = [("aws_access_key", "AKIAEXAMPLE", "http://x/app.js")]
    crawl.write_artifacts(art, tmp_path)
    mode = stat.S_IMODE(os.stat(tmp_path / "secrets.txt").st_mode)
    assert mode == 0o600
    # artefatos não sensíveis não precisam ser 0600 (só o run dir os protege)
    assert (tmp_path / "all-urls.txt").is_file()


def test_scope_partition_blocks_external_hosts():
    art = crawl.CrawlArtifacts()
    art.all_urls = ["https://app.example.com/a", "https://api.example.com/b",
                    "https://evil.com/x", "/relative/only"]
    art.js_endpoints = ["https://tracker.thirdparty.com/t.js", "/api/v1/x"]
    art.subdomains = ["app.example.com", "evil.com", "cdn.other.net"]
    entries = [scope.parse_scope_text("*.example.com", Path("t.txt"))]
    inscope, external = crawl.scope_partition(art, entries, "app.example.com", override=False)
    assert "https://app.example.com/a" in inscope
    assert "https://api.example.com/b" in inscope      # *.example.com cobre irmãos
    assert "/relative/only" in inscope                 # same-origin
    assert "https://evil.com/x" not in inscope         # NÃO será probado
    assert set(external) == {"evil.com", "tracker.thirdparty.com", "cdn.other.net"}


def test_scope_partition_override_restricts_to_target_domain():
    art = crawl.CrawlArtifacts()
    art.all_urls = ["https://app.target.com/a", "https://sub.target.com/b", "https://other.com/c"]
    art.js_endpoints = []
    art.subdomains = []
    # sem scope files, override=True: só o alvo e seus subdomínios entram
    inscope, external = crawl.scope_partition(art, [], "target.com", override=True)
    assert "https://app.target.com/a" in inscope
    assert "https://sub.target.com/b" in inscope
    assert "https://other.com/c" not in inscope
    assert external == ["other.com"]


def test_split_extra():
    assert crawl.split_extra('-foo "a b" -bar') == ["-foo", "a b", "-bar"]
    assert crawl.split_extra(None) == []


def _rec(endpoint, body=""):
    return json.dumps({"request": {"endpoint": endpoint},
                       "response": {"body": body}})


def test_process_jsonl_mines_js_endpoints_and_params(tmp_path):
    js_body = ('var A="https://api.example.com/v2/orders?status=open";'
               'fetch("/api/v1/users?id=1&role=admin");'
               'load("/static/app.js");')
    html_body = ('<html><form action="/login" method="post">'
                 '<input name="user"><input name="pass"></form></html>')
    lines = [
        _rec("https://site.example.com/app.js", js_body),
        _rec("https://site.example.com/?q=1&page=2", html_body),
    ]
    jf = tmp_path / "output.jsonl"
    jf.write_text("\n".join(lines) + "\n", encoding="utf-8")

    art = crawl.process_jsonl(jf, scan_secrets=True)

    # rotas escondidas mineradas do body do JS
    assert "/api/v1/users?id=1&role=admin" in art.js_endpoints
    assert "https://api.example.com/v2/orders?status=open" in art.js_endpoints
    # endpoints de API consolidados (o /api/... do JS entra em api_endpoints)
    assert any("/api/v1/users" in a for a in art.api_endpoints)
    # host absoluto minerado vira subdomínio descoberto
    assert "api.example.com" in art.subdomains
    # wordlist de params = URL (q,page) + JS (status,id,role) + form (user,pass)
    for p in ("q", "page", "status", "id", "role", "user", "pass"):
        assert p in art.all_params, p
    assert art.records == 2


def test_process_jsonl_flags_interesting(tmp_path):
    lines = [
        _rec("https://site.example.com/index.html", "<html>ok</html>"),
        _rec("https://site.example.com/web.config", "<config/>"),
        _rec("https://site.example.com/backup.zip", "PK..."),
    ]
    jf = tmp_path / "output.jsonl"
    jf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    art = crawl.process_jsonl(jf, scan_secrets=False)
    assert "https://site.example.com/web.config" in art.interesting
    assert "https://site.example.com/backup.zip" in art.interesting
    assert "https://site.example.com/index.html" not in art.interesting


def test_process_jsonl_missing_file(tmp_path):
    art = crawl.process_jsonl(tmp_path / "nope.jsonl", scan_secrets=True)
    assert art.records == 0 and art.all_urls == []


def test_process_jsonl_collects_sourcemap_refs(tmp_path):
    js = "var x=1;\n//# sourceMappingURL=app.min.js.map\n"
    jf = tmp_path / "output.jsonl"
    jf.write_text(_rec("https://site.example.com/app.min.js", js) + "\n", encoding="utf-8")
    art = crawl.process_jsonl(jf, scan_secrets=False)
    assert art.sourcemap_refs == ["https://site.example.com/app.min.js.map"]
    assert art.js_with_sourcemap == ["https://site.example.com/app.min.js"]


def test_harvest_sourcemaps_is_scope_gated(tmp_path, monkeypatch):
    from srecon import fetch as fetchmod
    art = crawl.CrawlArtifacts()
    art.js = ["https://app.target.com/in.js", "https://cdn.evil.com/out.js"]
    fetched = []
    fake = json.dumps({"version": 3, "sources": ["s.js"],
                       "sourcesContent": ['fetch("/api/v1/secret");var k="ghp_' + "a" * 36 + '";']})

    def fake_get(url, **kw):
        fetched.append(url)
        return fake

    monkeypatch.setattr(fetchmod, "get", fake_get)
    # override=True, sem scope files: só o alvo target.com e seus subdomínios entram
    stats = crawl.harvest_sourcemaps(art, tmp_path, [], "target.com", override=True, scan_secrets=True)

    # SÓ o host in-scope teve o .map buscado; o host externo NUNCA foi tocado
    assert fetched == ["https://app.target.com/in.js.map"]
    assert stats["fetched"] == 1
    # o fonte recuperado alimenta endpoints e secrets
    assert "/api/v1/secret" in art.js_endpoints
    assert any(r == "github_token" for r, _f, _u in art.secrets)


def test_write_artifacts_secrets_severity_and_redaction(tmp_path):
    art = crawl.CrawlArtifacts()
    art.secrets = [("firebase_db", "app.firebaseio.com", "http://x/a.js"),
                   ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "http://x/b.js")]
    crawl.write_artifacts(art, tmp_path)
    md = (tmp_path / "secrets.md").read_text()
    assert md.index("## high") < md.index("## low")          # high antes de low
    assert "AKIAIOSFODNN7EXAMPLE" not in md                   # md nunca tem o valor cheio
    assert "AKIA…MPLE" in md
    txt = (tmp_path / "secrets.txt").read_text()
    assert "AKIAIOSFODNN7EXAMPLE" in txt                      # o .txt 0600 tem o valor cheio
    assert "high\taws_access_key" in txt

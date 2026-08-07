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
    assert crawl.build_seeds("example.com") == "https://example.com,http://example.com"
    assert crawl.build_seeds("https://example.com/") == "https://example.com/"


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


def test_process_jsonl_missing_file(tmp_path):
    art = crawl.process_jsonl(tmp_path / "nope.jsonl", scan_secrets=True)
    assert art.records == 0 and art.all_urls == []

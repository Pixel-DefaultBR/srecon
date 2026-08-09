from srecon import enrich


def test_url_host():
    assert enrich.url_host("https://a.b.com/x?y=1") == "a.b.com"
    assert enrich.url_host("http://user:pw@h.com:8443/p") == "h.com"
    assert enrich.url_host("https://[2001:db8::1]:443/p") == "2001:db8::1"
    assert enrich.url_host("not a url") is None


def test_is_js():
    assert enrich.is_js("https://x.com/app.js")
    assert enrich.is_js("https://x.com/a/b.mjs")
    assert not enrich.is_js("https://x.com/app.json")
    assert not enrich.is_js("https://x.com/page")


def test_params():
    assert enrich.has_params("https://x.com/a?b=1&c=2")
    assert not enrich.has_params("https://x.com/a")
    assert enrich.param_names("https://x.com/a?b=1&c=2&b=3") == ["b", "c", "b"]


def test_is_api():
    assert enrich.is_api("https://x.com/api/users")
    assert enrich.is_api("https://x.com/v2/orders")
    assert enrich.is_api("https://x.com/graphql")
    assert enrich.is_api("https://x.com/data.json")
    assert not enrich.is_api("https://x.com/about")


def test_find_forms():
    html = ('<html><body>'
            '<form action="/login" method="post">'
            '<input name="user"><input name="pass"><input type="submit"></form>'
            '<form action="/search"><input name="q"></form></body></html>')
    forms = enrich.find_forms(html)
    assert len(forms) == 2
    assert forms[0]["method"] == "POST"
    assert forms[0]["action"] == "/login"
    assert forms[0]["inputs"] == ["user", "pass"]
    assert forms[1]["method"] == "GET"
    assert enrich.find_forms("<p>no forms here</p>") == []


def test_extract_js_endpoints():
    js = (
        'const API = "https://api.example.com/v2/users";'
        'fetch("/api/v1/orders?id=1");'
        'const r = /\\/foo\\/(\\d+)/;'                 # regex — deve ser ignorado
        'var css = "//cdn.host/x";'                    # protocol-relative — ignorado
        'load("/static/app.js");'
        'const t = `/tpl/${id}/x`;'                    # template com ${} — ruído, ignorado
        'x("not a path");'                             # sem barra inicial — ignorado
    )
    eps = enrich.extract_js_endpoints(js)
    assert "https://api.example.com/v2/users" in eps
    assert "/api/v1/orders?id=1" in eps
    assert "/static/app.js" in eps
    assert not any("//cdn" in e for e in eps)
    assert not any("${" in e for e in eps)
    assert not any(c in "".join(eps) for c in "()\\")


def test_extract_js_endpoints_rejects_viewstate_blob():
    # regressão de campo (testaspnet.vulnweb.com): __VIEWSTATE base64 não é rota
    vs = ('"/wEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4u'
          'YXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZArjxDMCoNA8" '
          '"/wEed29uZHdvbmQ9=="')
    eps = enrich.extract_js_endpoints(vs)
    assert eps == set()                              # nenhum blob vira endpoint
    # e uma rota real no meio ainda é pega
    assert "/login.aspx" in enrich.extract_js_endpoints('a("/login.aspx")')


def test_extract_js_params():
    js = 'fetch("/api/search?q=x&page=2&sort_by=date");' 'go("/a?id=1");' 'noise("/b?=&x")'
    params = enrich.extract_js_params(js)
    assert {"q", "page", "sort_by", "id"}.issubset(params)
    assert "" not in params
    assert enrich.extract_js_params("var x = 1;") == set()


def test_is_interesting():
    interessantes = [
        "https://x/.git/config", "https://x/backup.zip", "http://x/.env",
        "https://x/web.config", "/actuator/env", "https://x/db.sql",
        "https://x/wp-config.php", "/phpmyadmin/", "https://x/id_rsa",
        "https://x/app.jar", "https://x/config.yml", "https://x/dump.sql?x=1",
    ]
    for u in interessantes:
        assert enrich.is_interesting(u), u
    banais = [
        "https://x/index.html", "https://x/style.css", "https://x/app.js",
        "https://x/about", "https://x/logo.png", "/api/v1/users",
    ]
    for u in banais:
        assert not enrich.is_interesting(u), u


def test_scan_secrets():
    text = ('var k = "AKIAIOSFODNN7EXAMPLE"; '
            'const g = "AIza' + "B" * 35 + '"; '
            'api_key: "supersecret123"')
    hits = enrich.scan_secrets(text)
    rules = {r for r, _ in hits}
    assert "aws_access_key" in rules
    assert "google_api_key" in rules
    assert "generic_secret" in rules
    assert enrich.scan_secrets("") == []


def test_scan_secrets_new_high_signal_rules():
    samples = {
        "github_pat": "github_pat_" + "A" * 30,
        "gitlab_token": "glpat-" + "B" * 20,
        "openai_key": "sk-" + "C" * 40,
        "anthropic_key": "sk-ant-" + "D" * 30,
        "slack_webhook": "https://hooks.slack.com/services/T00000000/B11111111/" + "a" * 24,
        "sendgrid_key": "SG." + "x" * 20 + "." + "y" * 20,
        "db_connection_string": "mongodb://user:pass@db.internal:27017/app",
        "telegram_bot_token": "123456789:" + "Z" * 35,
        "npm_token": "npm_" + "e" * 36,
        "stripe_key": "sk_live_" + "f" * 24,
    }
    for rule, text in samples.items():
        rules = {r for r, _ in enrich.scan_secrets(text)}
        assert rule in rules, (rule, rules)


def test_scan_secrets_openai_vs_anthropic():
    rules = {r for r, _ in enrich.scan_secrets("sk-ant-" + "A" * 30)}
    assert "anthropic_key" in rules
    assert "openai_key" not in rules            # o lookahead evita casar como openai


def test_generic_secret_entropy_filter():
    for junk in ('api_key: "YOUR_API_KEY_HERE"', 'password="changeme"',
                 'secret = "xxxxxxxxxx"', 'auth_token = "{{PLACEHOLDER}}"'):
        assert not any(r == "generic_secret" for r, _ in enrich.scan_secrets(junk)), junk
    assert any(r == "generic_secret" for r, _ in enrich.scan_secrets('api_key: "s7Kf2pQx9zLmA3vB"'))


def test_scan_secrets_fragment_is_single_line():
    # \s nas regras (bearer/aws_secret/...) pode casar \n/\t; o frag NÃO pode quebrar
    # a linha do TSV do secrets.txt.
    txt = "Authorization: Bearer\n\t" + "a" * 30
    hits = enrich.scan_secrets(txt)
    assert any(r == "bearer" for r, _ in hits)
    for _r, frag in hits:
        assert "\n" not in frag and "\r" not in frag and "\t" not in frag


def test_secret_severity_and_redact():
    assert enrich.secret_severity("aws_access_key") == "high"
    assert enrich.secret_severity("firebase_db") == "low"
    assert enrich.secret_severity("desconhecida") == "medium"
    assert enrich.redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
    assert enrich.redact_secret("abc") == "ab…"
    full = "sk-ant-" + "Z" * 40
    assert full not in enrich.redact_secret(full)   # nunca revela o segredo inteiro


def test_extract_js_routes():
    js = ('fetch("api/v1/users");'
          'axios.get("/orders?id=1");'
          'xhr.open("GET", "/v2/data.json");'
          '$.get("api/legacy/thing");'
          'foo.get("notaroute");'          # relativo sem cara de API -> ignorado
          'x.open("POST", "notaroute2");'  # idem (2º arg do open)
          'fetch(`/tpl/${id}`);')          # template -> ignorado
    routes = enrich.extract_js_routes(js)
    assert "api/v1/users" in routes
    assert "/orders?id=1" in routes
    assert "/v2/data.json" in routes
    assert "api/legacy/thing" in routes
    assert "notaroute" not in routes
    assert "notaroute2" not in routes
    assert not any("${" in r for r in routes)
    assert enrich.extract_js_routes("") == set()


def test_find_sourcemap_refs():
    js = "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
    assert enrich.find_sourcemap_refs(js, "https://x.com/static/app.min.js") == \
        ["https://x.com/static/app.min.js.map"]
    # data: URI inline é ignorado
    assert enrich.find_sourcemap_refs("//# sourceMappingURL=data:application/json;base64,e30=") == []
    # //@ também é aceito; sem js_url devolve a ref crua
    assert enrich.find_sourcemap_refs("//@ sourceMappingURL=/a/b.map") == ["/a/b.map"]


def test_sourcemap_guess():
    assert enrich.sourcemap_guess("https://x.com/a/app.js") == "https://x.com/a/app.js.map"
    assert enrich.sourcemap_guess("https://x.com/a/app.min.mjs") == "https://x.com/a/app.min.mjs.map"
    assert enrich.sourcemap_guess("https://x.com/page") is None
    assert enrich.sourcemap_guess("") is None


def test_parse_sourcemap():
    sm = ('{"version":3,"sources":["src/a.js","src/b.js"],'
          '"sourcesContent":["const A=1","const B=2"]}')
    res = enrich.parse_sourcemap(sm)
    assert res["recovered"] == 2
    assert res["sources"] == ["src/a.js", "src/b.js"]
    assert "const A=1" in res["contents"]
    # entradas inválidas -> vazio, sem crash
    assert enrich.parse_sourcemap("não é json")["recovered"] == 0
    assert enrich.parse_sourcemap("[1,2,3]")["recovered"] == 0
    assert enrich.parse_sourcemap("")["recovered"] == 0

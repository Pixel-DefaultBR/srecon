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

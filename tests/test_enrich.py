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

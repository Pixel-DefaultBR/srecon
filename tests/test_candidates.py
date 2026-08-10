from srecon import candidates as C


# ------------------------------ classificação ------------------------------ #

def test_classify_param_ssrf_and_redirect_with_url_value():
    cands = C.classify_param("url", "https://evil.com")
    classes = {c.vuln_class for c in cands}
    assert "ssrf" in classes and "open_redirect" in classes
    ssrf = next(c for c in cands if c.vuln_class == "ssrf")
    assert ssrf.severity == "critical"
    assert ssrf.confidence >= 80          # nome forte + valor URL


def test_classify_param_idor_numeric_value():
    cands = C.classify_param("user_id", "1337")
    idor = next(c for c in cands if c.vuln_class == "idor")
    assert idor.severity == "high"
    assert idor.confidence > C.classify_param("user_id", "")[0].confidence  # valor eleva


def test_classify_param_xss_html_value_is_strong():
    cands = C.classify_param("q", "<script>")
    xss = next(c for c in cands if c.vuln_class == "xss")
    assert xss.confidence >= 85           # reflexão de < > provável


def test_classify_param_unknown_name_no_candidate():
    assert C.classify_param("csrftoken", "abc") == []
    assert C.classify_param("", "x") == []


def test_classify_urls_dedups_by_class_param_keeps_best():
    urls = [
        "https://a.example.com/p?redirect=/home",        # redirect, sem evidência de URL
        "https://a.example.com/q?redirect=https://x",    # redirect, valor URL (maior conf)
        "https://a.example.com/r?id=5",
    ]
    cands = C.classify_urls(urls)
    reds = [c for c in cands if c.vuln_class == "open_redirect" and c.param == "redirect"]
    assert len(reds) == 1                                 # dedup por (classe, param)
    assert reds[0].example == "https://a.example.com/q?redirect=https://x"  # o de maior conf


def test_classify_urls_sorted_by_severity_then_confidence():
    urls = ["https://a/x?url=https://e&q=<b>&id=1"]
    cands = C.classify_urls(urls)
    sevs = [c.severity for c in cands]
    # critical (ssrf) antes de high antes de medium
    assert sevs == sorted(sevs, key=lambda s: C.SEVERITY_ORDER[s])


def test_min_confidence_filters():
    urls = ["https://a/x?id="]        # id sem valor -> conf baixa
    hi = C.classify_urls(urls, min_confidence=90)
    assert hi == []


# ------------------------------- takeover ---------------------------------- #

def test_match_cname_service():
    assert C.match_cname_service("myapp.herokudns.com").service == "heroku"
    assert C.match_cname_service("foo.github.io").service == "github-pages"
    assert C.match_cname_service("bucket.s3.amazonaws.com").service == "aws-s3"
    assert C.match_cname_service("legit.example.com") is None


def test_assess_takeover_passive_vs_verified():
    passive = C.assess_takeover("sub.example.com", "x.github.io")
    assert passive.vuln_class == "subdomain_takeover"
    assert passive.confidence == 55 and passive.evidence["verified"] is False

    confirmed = C.assess_takeover("sub.example.com", "x.github.io",
                                  body="There isn't a GitHub Pages site here")
    assert confirmed.confidence == 95 and confirmed.evidence["verified"] is True

    claimed = C.assess_takeover("sub.example.com", "x.github.io", body="<html>real site</html>")
    assert claimed.confidence == 25 and claimed.evidence["verified"] is False


def test_assess_takeover_none_for_unknown_cname():
    assert C.assess_takeover("sub.example.com", "legit.example.com") is None


def test_body_indicates_takeover():
    fp = C.match_cname_service("x.herokudns.com")
    assert C.body_indicates_takeover(fp, "No such app\n")
    assert not C.body_indicates_takeover(fp, "welcome home")


# ------------------------------- provas ativas ------------------------------ #

def test_replace_param_only_target():
    got = C._replace_param("https://a/x?a=1&b=2", "b", "Z")
    assert "a=1" in got and "b=Z" in got


def test_probe_open_redirect_detects_canary(monkeypatch):
    def fake_open(url, timeout, data=None, headers=None, follow=True):
        return 302, {"location": f"https://{C.REDIRECT_CANARY_HOST}/x"}, ""
    monkeypatch.setattr(C, "_open", fake_open)
    out = C.probe_open_redirect("https://a/x?next=/home", "next")
    assert out["verified"] is True


def test_probe_open_redirect_negative(monkeypatch):
    monkeypatch.setattr(C, "_open", lambda *a, **k: (200, {}, ""))
    assert C.probe_open_redirect("https://a/x?next=/home", "next")["verified"] is False


def test_probe_cors_exploitable(monkeypatch):
    def fake_open(url, timeout, data=None, headers=None, follow=True):
        return 200, {"access-control-allow-origin": C.CORS_ORIGIN,
                     "access-control-allow-credentials": "true"}, ""
    monkeypatch.setattr(C, "_open", fake_open)
    out = C.probe_cors("https://a/api/x")
    assert out["verified"] and out["exploitable"]


def test_probe_graphql_introspection(monkeypatch):
    monkeypatch.setattr(C, "_open", lambda *a, **k: (200, {}, '{"data":{"__schema":{}}}'))
    assert C.probe_graphql("https://a/graphql")["verified"] is True


def test_probe_reflection(monkeypatch):
    monkeypatch.setattr(C, "_open", lambda *a, **k: (200, {}, f"echo {C.XSS_CANARY} back"))
    assert C.probe_reflection("https://a/x?q=1", "q")["verified"] is True

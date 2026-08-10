from srecon import triage as T


def test_cvss_severity_buckets():
    assert T.cvss_severity(9.8) == "critical"
    assert T.cvss_severity(7.5) == "high"
    assert T.cvss_severity(5.0) == "medium"
    assert T.cvss_severity(2.1) == "low"
    assert T.cvss_severity(None) == "medium"
    assert T.cvss_severity("nan") == "medium"


def test_lead_score_and_verified_bonus():
    a = T.Lead("bug", "ssrf: url", "critical", "candidates", confidence=90)
    b = T.Lead("bug", "ssrf: url", "critical", "candidates", confidence=90, verified=True)
    assert a.score == 400 + 90
    assert b.score == 400 + 90 + T.VERIFIED_BONUS
    assert b.score > a.score


def test_leads_from_candidates():
    data = [
        {"class": "ssrf", "severity": "critical", "param": "url", "confidence": 90,
         "example": "https://a/x?url=1", "evidence": {"verified": True}},
        {"class": "subdomain_takeover", "severity": "high", "param": "sub.a.com",
         "confidence": 95, "evidence": {"verified": True, "cname": "x.github.io"}},
    ]
    leads = T.leads_from_candidates(data)
    cats = {l.category for l in leads}
    assert cats == {"bug", "takeover"}
    assert all(l.verified for l in leads)


def test_leads_from_host_maps_cvss_to_severity():
    host = {"ip": "203.0.113.7", "vulns": [
        {"cve": "CVE-2021-1", "cvss": 9.8, "verified": True},
        {"cve": "CVE-2020-2", "cvss": 5.0, "verified": False},
    ]}
    leads = T.leads_from_host(host)
    sev = {l.title.split()[0]: l.severity for l in leads}
    assert sev["CVE-2021-1"] == "critical"
    assert sev["CVE-2020-2"] == "medium"
    assert any(l.verified for l in leads)


def test_leads_from_urls_and_assets():
    assert T.leads_from_urls_interesting(["https://a/.git/config"])[0].category == "surface"
    al = T.leads_from_assets_outscope(["old.example.com"])
    assert al[0].category == "asset" and al[0].severity == "info"


def test_rank_orders_by_score_desc():
    leads = [
        T.Lead("surface", "s", "medium", "urls", confidence=50),
        T.Lead("bug", "ssrf", "critical", "candidates", confidence=90, verified=True),
        T.Lead("cve", "c", "high", "host", confidence=55),
    ]
    ranked = T.rank(leads)
    assert ranked[0].title == "ssrf"                    # critical+verified no topo
    assert [l.score for l in ranked] == sorted((l.score for l in leads), reverse=True)


def test_summarize_counts():
    leads = [
        T.Lead("bug", "a", "critical", "candidates"),
        T.Lead("bug", "b", "high", "candidates"),
        T.Lead("cve", "c", "high", "host"),
    ]
    s = T.summarize(leads)
    assert s["total"] == 3
    assert s["by_severity"]["high"] == 2
    assert s["by_category"]["bug"] == 2

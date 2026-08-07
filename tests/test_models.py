from srecon.models import HostReport, SearchMatch


def test_host_parse():
    data = {
        "ip_str": "203.0.113.7", "org": "ACME", "asn": "AS64500",
        "hostnames": ["a.example.com"], "ports": [443, 22],
        "data": [
            {"port": 443, "product": "nginx", "version": "1.25",
             "vulns": {"CVE-2021-23017": {"cvss": 9.8, "verified": True}},
             "_shodan": {"module": "https"}},
            {"port": 22, "product": "OpenSSH"},
        ],
    }
    rep = HostReport.from_shodan(data)
    assert rep.ip == "203.0.113.7"
    assert rep.ports == [22, 443]
    assert rep.services[0].port == 22          # ordenado por porta
    assert len(rep.vulns) == 1
    assert rep.vulns[0].cvss == 9.8


def test_host_parse_empty():
    rep = HostReport.from_shodan({"ip_str": "1.1.1.1"})
    assert rep.ip == "1.1.1.1"
    assert rep.services == []
    assert rep.vulns == []


def test_search_match():
    m = SearchMatch.from_match({
        "ip_str": "203.0.113.7", "port": 443, "org": "ACME",
        "location": {"country_name": "Brazil"}, "data": "HTTP/1.1 200 OK\r\n",
    })
    assert m.ip == "203.0.113.7"
    assert m.country == "Brazil"
    assert m.data_preview.startswith("HTTP/1.1 200 OK")

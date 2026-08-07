from srecon import cvedb
from srecon.commands import cve as cve_cmd
from srecon.models import CveDetail, HostReport


def test_cvedetail_from_api():
    d = CveDetail.from_api({
        "cve_id": "CVE-2021-44228", "summary": "log4shell", "cvss": 10.0,
        "cvss_v3": 10.0, "epss": 0.99999, "ranking_epss": 1.0, "kev": True,
        "ransomware_campaign": "Known", "references": ["a", "b"], "cpes": ["cpe:x"],
    })
    assert d.cve_id == "CVE-2021-44228"
    assert d.cvss_v3 == 10.0 and d.kev is True
    assert d.epss == 0.99999 and d.references == ["a", "b"]


def _write_host(base, name, shodan_data):
    d = base / name / "20260807T000000Z"
    d.mkdir(parents=True)
    rep = HostReport.from_shodan(shodan_data)
    (d / "host.json").write_text(rep.model_dump_json(), encoding="utf-8")


def test_aggregate_reports_cross_host(tmp_path):
    reports = tmp_path / "reports"
    _write_host(reports, "host-a", {
        "ip_str": "203.0.113.1",
        "data": [{"port": 443, "vulns": {"CVE-2021-44228": {"cvss": 10.0, "verified": True},
                                          "CVE-2019-0001": {"cvss": 5.0}}}],
    })
    _write_host(reports, "host-b", {
        "ip_str": "203.0.113.2",
        "data": [{"port": 8080, "vulns": {"CVE-2021-44228": {"cvss": 9.0}}}],
    })
    aggs = cve_cmd.aggregate_reports(reports)
    by = {a.cve: a for a in aggs}
    assert by["CVE-2021-44228"].count == 2                 # em 2 hosts
    assert set(by["CVE-2021-44228"].hosts) == {"203.0.113.1", "203.0.113.2"}
    assert by["CVE-2021-44228"].max_cvss == 10.0           # pega o maior
    assert by["CVE-2021-44228"].verified is True
    # ordenado por CVSS desc -> log4shell primeiro
    assert aggs[0].cve == "CVE-2021-44228"
    # filtro min_cvss
    high = cve_cmd.aggregate_reports(reports, min_cvss=8.0)
    assert [a.cve for a in high] == ["CVE-2021-44228"]


def test_aggregate_reports_empty(tmp_path):
    assert cve_cmd.aggregate_reports(tmp_path / "nada") == []


def test_lookup_dedup_and_errors(monkeypatch):
    calls = []

    def fake_get(cid, timeout=15.0):
        calls.append(cid)
        if cid == "CVE-0000-0001":
            raise cvedb.CvedbError("404")
        return CveDetail(cve_id=cid)

    monkeypatch.setattr(cvedb, "get_cve", fake_get)
    details, errors = cve_cmd.lookup(
        ["CVE-2021-44228", "cve-2021-44228", "CVE-0000-0001"])  # 2ª é dup (case)
    assert [d.cve_id for d in details] == ["CVE-2021-44228"]
    assert calls == ["CVE-2021-44228", "CVE-0000-0001"]        # dup não bate de novo
    assert errors and errors[0][0] == "CVE-0000-0001"

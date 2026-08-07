import pytest

from srecon import msf
from srecon.commands import msf as msf_cmd
from srecon.models import HostReport

# metadata sintético no formato do ~/.msf4/store/modules_metadata.json
FAKE = {
    "exploit_multi/http/log4shell": {
        "fullname": "exploit/multi/http/log4shell_header_injection",
        "name": "Log4Shell HTTP Header Injection", "type": "exploit", "rank": 600,
        "disclosure_date": "2021-12-10", "platform": "Java",
        "references": ["CVE-2021-44228", "URL-https://x"],
    },
    "aux_scanner/log4shell": {
        "fullname": "auxiliary/scanner/http/log4shell_scanner",
        "name": "Log4Shell scanner", "type": "auxiliary", "rank": 300,
        "references": ["CVE-2021-44228"],
    },
    "exploit_vsftpd": {
        "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
        "name": "VSFTPD v2.3.4 Backdoor Command Execution", "type": "exploit", "rank": 600,
        "references": ["CVE-2011-2523", "OSVDB-73573"],
    },
    "post_thing": {
        "fullname": "post/linux/gather/enum_stuff",
        "name": "linux gather", "type": "post", "rank": 300, "references": [],
    },
}


def test_normalize_and_cves_from_refs():
    assert msf.normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert msf.normalize_cve("not-a-cve") is None
    assert msf.cves_from_refs(["CVE-2011-2523", "OSVDB-1", "CVE-2011-2523"]) == ["CVE-2011-2523"]


def test_index_by_cve_sorted_by_rank():
    idx = msf.MsfIndex(FAKE)
    assert len(idx) == 4
    mods = idx.by_cve("CVE-2021-44228")
    assert [m.fullname for m in mods][0].endswith("log4shell_header_injection")  # rank 600 primeiro
    assert len(mods) == 2
    assert idx.by_cve("CVE-0000-0000") == []


def test_index_by_keyword_and_type_filter():
    idx = msf.MsfIndex(FAKE)
    hits = idx.by_keyword("vsftpd", types=("exploit", "auxiliary"))
    assert len(hits) == 1 and "vsftpd" in hits[0].fullname
    # 'post' fica de fora quando filtramos por exploit/auxiliary
    assert idx.by_keyword("gather", types=("exploit", "auxiliary")) == []
    assert len(idx.by_keyword("gather", types=("post",))) == 1


def test_match_host_extracts_cves_and_products():
    idx = msf.MsfIndex(FAKE)
    rep = HostReport.from_shodan({
        "ip_str": "203.0.113.9",
        "data": [
            {"port": 21, "product": "vsftpd", "version": "2.3.4",
             "vulns": {"CVE-2011-2523": {"cvss": 10.0}}},
            {"port": 8080, "product": "Apache Tomcat",
             "vulns": {"CVE-2021-44228": {"cvss": 10.0}}},
        ],
    })
    res = msf_cmd.match_host(idx, rep)
    assert res.rhosts == "203.0.113.9"
    cve_map = {h.cve: h for h in res.cve_hits}
    assert cve_map["CVE-2021-44228"].modules  # casou
    assert cve_map["CVE-2011-2523"].modules
    names = res.module_names()
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in names
    # sem duplicatas
    assert len(names) == len(set(names))


def test_resource_script_is_triage_only():
    rc = msf.build_resource_script("10.0.0.5", ["exploit/unix/ftp/vsftpd_234_backdoor"], rport=21)
    assert "use exploit/unix/ftp/vsftpd_234_backdoor" in rc
    assert "setg RHOSTS 10.0.0.5" in rc
    assert "set RPORT 21" in rc
    # NUNCA dispara automaticamente
    low = rc.lower()
    assert "\nrun" not in low and "exploit\n" not in low.replace("use exploit", "")
    assert "info" in rc


def test_load_index_missing_file(tmp_path):
    with pytest.raises(msf.MsfError):
        msf.load_index(tmp_path / "nope.json")

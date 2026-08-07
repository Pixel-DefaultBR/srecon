import pytest
import shodan

from srecon.shodan_client import ShodanClient, ShodanClientError


def test_search_passes_minify_false_and_keeps_banner():
    c = ShodanClient("k", rate_delay=0)

    captured = []

    def fake_search(query, **kw):
        captured.append(kw)
        return {"total": 1, "facets": {},
                "matches": [{"ip_str": "1.2.3.4", "port": 443,
                             "data": "HTTP/1.1 200 OK\r\nServer: nginx"}]}

    c._api.search = fake_search
    res = c.search("nginx", limit=1)
    assert captured and captured[0].get("minify") is False      # C2
    assert res.matches[0].data_preview.startswith("HTTP/1.1 200 OK")


def test_retry_fires_on_lib_connection_error(monkeypatch):
    monkeypatch.setattr("srecon.shodan_client.time.sleep", lambda s: None)
    c = ShodanClient("k", retries=3)
    n = {"c": 0}

    def flaky():
        n["c"] += 1
        if n["c"] < 3:
            raise shodan.APIError("Unable to connect to Shodan")   # C3: string real da lib
        return {"query_credits": 7}

    c._api.info = flaky
    info = c.info()
    assert n["c"] == 3 and info.query_credits == 7


def test_no_retry_on_terminal_error(monkeypatch):
    monkeypatch.setattr("srecon.shodan_client.time.sleep", lambda s: None)
    c = ShodanClient("k", retries=3)
    n = {"c": 0}

    def bad():
        n["c"] += 1
        raise shodan.APIError("Invalid API key")

    c._api.info = bad
    with pytest.raises(ShodanClientError):
        c.info()
    assert n["c"] == 1        # erro terminal não re-tenta

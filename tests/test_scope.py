from pathlib import Path

from srecon import scope


def _entry(text):
    return scope.parse_scope_text(text, Path("t.txt"))


def test_wildcard_domain_and_subdomain():
    e = _entry("Autorizado *.cloudwiser.com.br")
    assert scope.match("cloudwiser.com.br", [e])
    assert scope.match("cortex.cloudwiser.com.br", [e])
    assert scope.match("a.b.cloudwiser.com.br", [e])


def test_url_and_port_stripped():
    e = _entry("*.example.com")
    assert scope.match("https://a.example.com/path?x=1", [e])
    assert scope.match("a.example.com:8443", [e])


def test_reject_unrelated():
    e = _entry("*.example.com")
    assert scope.match("example.com.evil.net", [e]) is None
    assert scope.match("notexample.com", [e]) is None


def test_cidr_and_ip():
    e = _entry("range 198.51.100.0/24 e host 203.0.113.9")
    assert scope.match("198.51.100.42", [e])
    assert scope.match("203.0.113.9", [e])
    assert scope.match("8.8.8.8", [e]) is None


def test_empty_target():
    e = _entry("*.example.com")
    assert scope.match("", [e]) is None


def test_reject_comma_and_whitespace():
    e = _entry("*.example.com")
    # vírgula/whitespace embutidos viram múltiplos seeds -> nunca autoriza
    assert scope.match("a.example.com,evil.com", [e]) is None
    assert scope.match("a.example.com\nevil.com", [e]) is None


def test_ipv6_address_and_cidr():
    e = _entry("Autorizado ::1 e 2001:db8::/32")
    assert scope.match("::1", [e])
    assert scope.match("http://[2001:db8::dead]/x", [e])
    assert scope.match("[2001:db8::1]:8443", [e])
    assert scope.match("2001:dead::1", [e]) is None


def test_find_forms_unclosed_flush():
    from srecon import enrich
    # dois <form> sem fechar o primeiro: nenhum pode ser perdido
    forms = enrich.find_forms("<form action=/a><input name=x><form action=/b><input name=y>")
    actions = sorted(f["action"] for f in forms)
    assert actions == ["/a", "/b"]

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


def test_negation_and_comment_lines_do_not_authorize():
    # regressão do bug guloso: nota de exclusão/comentário NUNCA autoriza
    text = ("Autorizado: prod.cliente.com\n"
            "# comentario menciona staging.cliente.com\n"
            "Fora de escopo (NAO TOCAR): partner.terceiro.com\n"
            "// out of scope: 8.8.8.8\n"
            "excluir range: 10.0.0.0/8\n")
    e = _entry(text)
    assert scope.match("prod.cliente.com", [e])                 # única linha de allow
    assert scope.match("partner.terceiro.com", [e]) is None     # linha de negação
    assert scope.match("staging.cliente.com", [e]) is None      # comentário '#'
    assert scope.match("8.8.8.8", [e]) is None                  # comentário '//'
    assert scope.match("10.0.0.5", [e]) is None                 # 'excluir' + CIDR


def test_deny_wins_over_allow_wildcard():
    # furo HIGH #1: allow wildcard NÃO pode re-autorizar host explicitamente negado.
    text = ("*.example.com\n"
            "# Out of scope:\n"
            "admin.example.com\n"
            "secret.example.com\n")
    e = _entry(text)
    assert scope.match("api.example.com", [e])                  # coberto pelo wildcard
    assert scope.match("admin.example.com", [e]) is None        # negado apesar do wildcard
    assert scope.match("secret.example.com", [e]) is None       # mesma seção de exclusão
    assert scope.is_denied("admin.example.com", [e])
    assert not scope.is_denied("api.example.com", [e])


def test_deny_section_closes_on_blank_line():
    # a seção de exclusão termina na linha em branco: o que vem depois volta a ALLOW.
    text = ("# out of scope\n"
            "old.example.com\n"
            "\n"
            "api.example.com\n")
    e = _entry(text)
    assert scope.match("old.example.com", [e]) is None          # dentro da seção deny
    assert scope.match("api.example.com", [e])                  # após a linha em branco


def test_deny_cidr_wins_over_allow_cidr():
    # negar sub-range dentro de um allow maior: o sub-range fica fora.
    text = ("10.0.0.0/8\n"
            "# exclude:\n"
            "10.1.2.0/24\n")
    e = _entry(text)
    assert scope.match("10.9.9.9", [e])                         # allow amplo
    assert scope.match("10.1.2.50", [e]) is None                # sub-range negado
    assert scope.is_denied("10.1.2.50", [e])


def test_deny_is_global_across_entries():
    # deny num arquivo bloqueia allow de OUTRO arquivo (avaliação global).
    allow = scope.parse_scope_text("*.example.com", Path("allow.txt"))
    deny = scope.parse_scope_text("Fora de escopo: admin.example.com", Path("deny.txt"))
    assert scope.match("admin.example.com", [allow, deny]) is None
    assert scope.match("admin.example.com", [deny, allow]) is None   # ordem não importa
    assert scope.match("api.example.com", [allow, deny])


def test_inline_negation_does_not_leak_to_next_line():
    # negação inline vale só pra própria linha; a seguinte continua allow.
    text = ("bad.example.com (out of scope)\n"
            "good.example.com\n")
    e = _entry(text)
    assert scope.match("bad.example.com", [e]) is None
    assert scope.match("good.example.com", [e])


def test_normalize_host_strips_query_and_fragment():
    e = _entry("*.example.com")
    assert scope.match("https://a.example.com?x=1", [e])        # '?' sem '/' antes
    assert scope.match("https://a.example.com#frag", [e])


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

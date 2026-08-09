"""Modo 'auto' — helpers puros (roteamento de argv + detecção de IP).

A orquestração em si mora no comando `auto` do cli.py (reusa os outros comandos);
aqui ficam só as peças puras e testáveis.
"""
from __future__ import annotations

import ipaddress


def looks_like_ip(target: str) -> bool:
    """True se o alvo (já sem esquema/porta/path) é um IPv4/IPv6 literal."""
    t = (target or "").strip()
    if not t:
        return False
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def route_argv(argv: list, known: set) -> list:
    """Roteia 'srecon <alvo>' -> 'srecon auto <alvo>'.

    Se o 1º token que não começa com '-' NÃO for um comando conhecido, insere 'auto'
    imediatamente antes dele. Preserva: subcomandos conhecidos, invocações só com
    flags globais (--help/--version, sem alvo) e 'auto' explícito. Não precisa pular
    valores de flag porque o grupo não tem opções que consomem valor.
    """
    out = list(argv)
    for i, tok in enumerate(out):
        if tok.startswith("-"):
            continue
        if tok in known:
            return out                 # subcomando conhecido -> intacto
        out.insert(i, "auto")          # alvo solto -> vira 'auto <alvo>'
        return out
    return out                         # só flags (ou vazio) -> intacto

"""GET HTTP mínimo e defensivo p/ downloads pontuais (ex: sourcemaps do crawl).

Deliberadamente NÃO segue redirect: um 3xx poderia pular para um host fora de
escopo, então a decisão de escopo (feita pelo caller antes de chamar aqui) não
pode ser subvertida por um Location:. Só http/https, com teto de bytes e timeout.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

_UA = "srecon/0.2 (+recon; sourcemap-fetch)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None            # não segue: mantém o fetch preso ao host autorizado


def get(url: str, timeout: int = 15, max_bytes: int = 8_000_000,
        headers: dict | None = None, insecure: bool = True) -> str | None:
    """GET simples: retorna o corpo como texto (utf-8, replace) ou None em qualquer
    falha/redirect/tipo inesperado. Só http(s). `insecure` ignora erro de cert (alvos
    de recon costumam ter TLS quebrado); a decisão de escopo é do caller."""
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": _UA}
    if headers:
        h.update(headers)
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )
    req = urllib.request.Request(url, headers=h)
    try:
        with opener.open(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) not in (200, None):
                return None
            data = resp.read(max_bytes + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None
    except Exception:
        return None
    if not data:
        return None
    return data[:max_bytes].decode("utf-8", "replace")

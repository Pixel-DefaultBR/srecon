from __future__ import annotations

from ..models import SearchResult
from ..shodan_client import ShodanClient

DEFAULT_FIELDS = ["ip", "port", "org", "product", "country", "hostnames"]


def run(client: ShodanClient, query: str, facets: list[str] | None, limit: int) -> SearchResult:
    # A lib do shodan chama create_facet_string(facets) e ITERA o argumento: precisa ser
    # uma LISTA de nomes (['country','org']). Passar a string já concatenada corrompe a query.
    return client.search(query, facets=facets or None, limit=limit)


def run_count(client: ShodanClient, query: str, facets: list[str] | None) -> dict:
    return client.count(query, facets=facets or None)

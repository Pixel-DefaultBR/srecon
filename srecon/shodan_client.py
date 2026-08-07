from __future__ import annotations

import time

import shodan

from .models import HostReport, PlanInfo, SearchMatch, SearchResult, FacetItem


class ShodanClientError(Exception):
    pass


_TRANSIENT = ("rate limit", "timeout", "timed out", "temporar", "502", "503", "504")


class ShodanClient:
    def __init__(self, api_key: str, rate_delay: float = 1.0, retries: int = 3):
        self._api = shodan.Shodan(api_key)
        self.rate_delay = max(rate_delay, 0.0)
        self.retries = max(retries, 1)

    def _retry(self, fn, *args, **kwargs):
        last = None
        for attempt in range(self.retries):
            try:
                return fn(*args, **kwargs)
            except shodan.APIError as e:
                last = e
                if any(t in str(e).lower() for t in _TRANSIENT) and attempt < self.retries - 1:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                raise ShodanClientError(str(e)) from e
        raise ShodanClientError(f"falha após {self.retries} tentativas: {last}")

    def info(self) -> PlanInfo:
        d = self._retry(self._api.info)
        return PlanInfo(
            plan=d.get("plan"),
            query_credits=d.get("query_credits"),
            scan_credits=d.get("scan_credits"),
            monitored_ips=d.get("monitored_ips"),
            unlocked=d.get("unlocked"),
            https=d.get("https"),
            telnet=d.get("telnet"),
        )

    def host(self, ip: str, history: bool = False, minify: bool = False) -> HostReport:
        d = self._retry(self._api.host, ip, history=history, minify=minify)
        return HostReport.from_shodan(d)

    def count(self, query: str, facets=None) -> dict:
        return self._retry(self._api.count, query, facets=facets)

    def search(self, query: str, facets=None, limit: int = 100) -> SearchResult:
        matches: list[SearchMatch] = []
        first = self._retry(self._api.search, query, facets=facets, page=1)
        total = first.get("total", 0) or 0

        def _absorb(page_matches) -> bool:
            for m in page_matches:
                matches.append(SearchMatch.from_match(m))
                if len(matches) >= limit:
                    return True
            return False

        done = _absorb(first.get("matches", []) or [])
        page = 2
        while not done and len(matches) < total:
            time.sleep(self.rate_delay)
            try:
                res = self._retry(self._api.search, query, page=page)
            except ShodanClientError:
                # Paginação além da 1ª página pode exigir plano superior; em vez de
                # descartar tudo, devolve o que já foi coletado.
                break
            got = res.get("matches", []) or []
            if not got:
                break
            done = _absorb(got)
            page += 1

        facets_out: dict[str, list[FacetItem]] = {}
        for name, items in (first.get("facets", {}) or {}).items():
            facets_out[name] = [
                FacetItem(value=str(i.get("value")), count=int(i.get("count", 0))) for i in items
            ]
        return SearchResult(query=query, total=total, matches=matches, facets=facets_out)

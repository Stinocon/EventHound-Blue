from __future__ import annotations

import asyncio
import inspect
import os
import sys
import time
from urllib.parse import quote, urlparse

from ..config import RAG_DIR
from ..document import Document

_UA = "cyber-rag/0.1 (+local research; contact: workspace owner)"


def _require_web_egress() -> None:
    """Programmatic egress gate for web ingest (defense in depth on top of §15).

    Scraping/Wayback goes out over the network and exposes the public IP (blacklist risk).
    On top of the human confirmation + VPN required by §15, an explicit opt-in via env
    CY_ALLOW_WEB_EGRESS=1 is required here: so no crawl starts automatically or by mistake.
    Queries to the RAG and ingest of local sources (pdf/markdown) don't go through here and
    always remain available."""
    val = (os.getenv("CY_ALLOW_WEB_EGRESS") or "").strip().lower()
    if val not in ("1", "true", "yes", "on"):
        raise RuntimeError(
            "web egress disabled: web source ingest goes out over the network and exposes the IP (§15). "
            "Turn on the VPN, then set CY_ALLOW_WEB_EGRESS=1 to authorize the crawl."
        )


def wayback_snapshot(url: str, tries: int = 3) -> str | None:
    """URL of the most recent Wayback (archive.org) snapshot with status 200 for `url`, or None.

    Legitimate fallback when the site blocks bots (Cloudflare/WAF): archive.org isn't protected and
    the CDX API is public. The `id_/` suffix returns the original content without the archive.org
    toolbar. NOTE: it's still an outbound network call → subject to §15 (VPN + confirmation) like
    every crawl. Uses stdlib (urllib) to avoid assuming httpx."""
    _require_web_egress()
    import json
    import urllib.request
    cdx = ("https://web.archive.org/cdx/search/cdx?url=" + quote(url, safe="")
           + "&output=json&filter=statuscode:200&fl=timestamp&collapse=digest&limit=-5")
    for _ in range(tries):
        try:
            req = urllib.request.Request(cdx, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode("utf-8"))
            # rows[0] is the header (["timestamp"]); the last row is the most recent snapshot
            data = rows[1:] if rows and rows[0] == ["timestamp"] else rows
            if data:
                ts = data[-1][0]
                return f"https://web.archive.org/web/{ts}id_/{url}"
            # valid but empty response: could be a transient empty result/rate-limit from the CDX → retry
            print(f"    [wayback] empty CDX for {url}; retry", file=sys.stderr)
        except Exception as e:
            print(f"    [wayback] CDX unavailable for {url} ({type(e).__name__}); retry", file=sys.stderr)
        if _ < tries - 1:
            time.sleep(2)  # backoff: the CDX sometimes responds transiently empty/rate-limited
    return None

# ───────────────────────────────────────────────────────────────────────────
# VERSION NOTE: the crawl4ai API changes between releases. All calls to
# crawl4ai are isolated in this module. Optimization parameters are
# passed but FILTERED to those actually accepted by the installed version
# (see _supported_kwargs): so adding knobs doesn't break if a parameter
# doesn't exist. Deep-crawl is optional: if the classes aren't there, it degrades to
# crawling only the seed pages. Ref. https://docs.crawl4ai.com/.
# ───────────────────────────────────────────────────────────────────────────


def _supported_kwargs(cls, kwargs: dict) -> dict:
    """Keeps only the kwargs accepted by cls's constructor and not None."""
    try:
        params = set(inspect.signature(cls).parameters)
    except (TypeError, ValueError):
        return {k: v for k, v in kwargs.items() if v is not None}
    return {k: v for k, v in kwargs.items() if k in params and v is not None}


def _cache_mode(name):
    try:
        from crawl4ai import CacheMode
    except Exception:
        return None
    mapping = {
        "enabled": getattr(CacheMode, "ENABLED", None),
        "bypass": getattr(CacheMode, "BYPASS", None),
        "disabled": getattr(CacheMode, "DISABLED", None),
        "read_only": getattr(CacheMode, "READ_ONLY", None),
        "write_only": getattr(CacheMode, "WRITE_ONLY", None),
    }
    return mapping.get((name or "enabled").lower())


def _matches(url: str, include: list[str], exclude: list[str]) -> bool:
    """Patterns treated as substrings of the URL (consistent with sources.yaml)."""
    if include and not any(p in url for p in include):
        return False
    if exclude and any(p in url for p in exclude):
        return False
    return True


def _storage_state_path(auth: dict) -> str | None:
    if not (auth.get("required") and auth.get("method") == "storage_state"):
        return None
    sf = auth.get("storage_state_file")
    if not sf:
        return None
    return sf if str(sf).startswith("/") else str((RAG_DIR / sf).resolve())


def _result_text(result) -> str:
    md = getattr(result, "markdown", None)
    if md is None:
        return getattr(result, "cleaned_html", "") or ""
    return getattr(md, "raw_markdown", None) or (md if isinstance(md, str) else str(md))


def _iter_results(results):
    if results is None:
        return []
    return results if isinstance(results, list) else [results]


def load_web(source: dict) -> list[Document]:
    _require_web_egress()
    return asyncio.run(_crawl(source))


def _build_browser_cfg(BrowserConfig, cc: dict, storage_state):
    candidate = {
        "headless": True,
        "storage_state": storage_state,
        "user_agent": cc.get("user_agent"),
        "light_mode": cc.get("light_mode", True),   # lighter browser
        "text_mode": cc.get("text_mode", False),    # keep False for SPAs (rendering needed)
        "verbose": False,
    }
    return BrowserConfig(**_supported_kwargs(BrowserConfig, candidate))


def _build_run_cfg(CrawlerRunConfig, cc: dict, strategy):
    candidate = {
        "deep_crawl_strategy": strategy,
        "stream": False,
        # performance
        "cache_mode": _cache_mode(cc.get("cache_mode", "enabled")),
        "page_timeout": cc.get("page_timeout_ms"),
        # courtesy / anti-aggressiveness
        "check_robots_txt": cc.get("respect_robots", True),
        "mean_delay": cc.get("mean_delay"),
        "semaphore_count": cc.get("max_concurrency"),
        # content accuracy
        "word_count_threshold": cc.get("word_count_threshold"),
        "excluded_tags": cc.get("excluded_tags"),
        "exclude_external_links": cc.get("exclude_external_links"),
        "verbose": False,
    }
    return CrawlerRunConfig(**_supported_kwargs(CrawlerRunConfig, candidate))


async def _crawl(source: dict) -> list[Document]:
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig

    try:
        from crawl4ai.deep_crawling import BFSDeepCrawlStrategy
        from crawl4ai.deep_crawling.filters import DomainFilter, FilterChain, URLPatternFilter
        have_deep = True
    except Exception:
        have_deep = False

    cc = source.get("crawler", {})
    seeds = cc.get("seeds", [])
    include = cc.get("include_patterns", [])
    exclude = cc.get("exclude_patterns", [])
    max_depth = int(cc.get("max_depth", 2))
    max_pages = int(cc.get("max_pages", 300))

    browser_cfg = _build_browser_cfg(BrowserConfig, cc, _storage_state_path(cc.get("auth") or {}))

    domains = sorted({urlparse(s).netloc for s in seeds})
    docs: list[Document] = []
    seen: set[str] = set()

    async with AsyncWebCrawler(config=browser_cfg) as crawler:
        for seed in seeds:
            if len(docs) >= max_pages:
                break
            if have_deep:
                filters = [DomainFilter(allowed_domains=domains)]
                if include:
                    filters.append(URLPatternFilter(patterns=[f"*{p}*" for p in include]))
                strategy = BFSDeepCrawlStrategy(
                    max_depth=max_depth,
                    max_pages=max_pages,
                    filter_chain=FilterChain(filters),
                )
            else:
                strategy = None
            run_cfg = _build_run_cfg(CrawlerRunConfig, cc, strategy)

            results = await crawler.arun(url=seed, config=run_cfg)

            added_for_seed = 0
            for res in _iter_results(results):
                url = getattr(res, "url", seed)
                if url in seen:
                    continue
                seen.add(url)
                if not getattr(res, "success", True):
                    continue
                if not _matches(url, include, exclude):
                    continue
                text = _result_text(res)
                if not text.strip():
                    continue
                docs.append(Document(locator=url, text=text, metadata={"url": url}))
                added_for_seed += 1
                if len(docs) >= max_pages:
                    break

            # Wayback fallback: if the seed produced nothing (anti-bot block or empty page),
            # tries the archived snapshot of the seed page ONLY (not of the deep-crawl). Enabled
            # from sources.yaml with `crawler.wayback_fallback: true` (default off to avoid surprises).
            if added_for_seed == 0 and cc.get("wayback_fallback"):
                wb = wayback_snapshot(seed)
                if wb:
                    try:
                        # shallow config (strategy=None): the snapshot is a SINGLE page, no
                        # deep-crawl (the DomainFilter on the original site's domains doesn't
                        # apply to web.archive.org and would only waste effort on link discovery).
                        wb_cfg = _build_run_cfg(CrawlerRunConfig, cc, None)
                        wb_res = _iter_results(await crawler.arun(url=wb, config=wb_cfg))
                        for res in wb_res:
                            text = _result_text(res)
                            if text.strip():
                                docs.append(Document(locator=seed, text=text, metadata={"url": seed, "via": "wayback"}))
                                print(f"    [wayback] {seed} retrieved from archive.org", file=sys.stderr)
                                break
                    except Exception as e:
                        print(f"    [wayback] snapshot fetch failed for {seed} ({type(e).__name__})", file=sys.stderr)
    return docs

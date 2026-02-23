"""Shallow web crawler orchestration using Katana."""

import logging
import time
from typing import Dict, Set, Optional
from urllib.parse import urlparse

from .parser import KatanaParser
from .classifier import extract_params, canonical_endpoint, is_static_resource
from .hasher import hash_string, strip_default_port, compute_asset_fingerprint
from .manifest import build_manifest
from ..auth.context import AuthSessionContext

logger = logging.getLogger("vertigo.fingerprint.crawler")


class ShallowCrawler:
    """Shallow web crawler that creates stable manifests for change detection via Katana."""

    TRACKED_HEADERS = {
        "content-security-policy", "strict-transport-security",
        "permissions-policy", "x-frame-options", "referrer-policy",
    }

    def __init__(
        self,
        target: str,
        entry: str = "/",
        max_depth: int = 3,
        max_urls: int = 1000,
        timeout: int = 60,
        concurrency: int = 10,
        mute: bool = False,
        session: Optional[AuthSessionContext] = None,
    ):
        self.target = self._normalize_target(target)
        self.entry = entry
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.concurrency = concurrency
        self.mute = mute

        self.session_cookies = None
        if session and session.cookies:
            self.session_cookies = "; ".join(f"{c['name']}={c['value']}" for c in session.cookies)

        self.endpoints: Set[str] = set()
        self.static_resources: Dict[str, Dict] = {}
        self.headers: Dict[str, str] = {}
        self.cookies: Dict[str, Dict] = {}

        self.status = "COMPLETE"
        self.urls_crawled = 0
        self.partial = False

        self.parser = KatanaParser(mute=mute)

    def _normalize_target(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        parsed = urlparse(target)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    def _normalize_netloc(self, scheme: str, netloc: str) -> str:
        return strip_default_port(scheme, netloc.lower())

    def _is_same_origin(self, result_url: str, target_parsed) -> bool:
        result_parsed = urlparse(result_url)
        target_host = target_parsed.hostname
        result_host = result_parsed.hostname
        if not target_host or not result_host:
            return False
        return target_host.lower() == result_host.lower()

    def _process_results(self, results: list):
        target_parsed = urlparse(self.target)
        for result in results:
            url = result.get("url", "")
            method = result.get("method", "GET").upper()
            if not url:
                continue
            parsed = urlparse(url)
            if not self._is_same_origin(url, target_parsed):
                logger.debug("external_url_skipped  url=%r", url)
                continue
            self.urls_crawled += 1
            params = extract_params(url)
            path = parsed.path or "/"
            if is_static_resource(url):
                if path not in self.static_resources:
                    self.static_resources[path] = {"path": path, "url": url, "content_hash": hash_string(url)}
            else:
                self.endpoints.add(canonical_endpoint(method, url, params))

    def crawl(self) -> Dict:
        scan_begin = time.time_ns() // 1_000_000
        logger.debug("crawl_start  target=%r  depth=%d  urls=%d  timeout=%ds",
                     self.target, self.max_depth, self.max_urls, self.timeout)

        start_url = self.target if self.entry == "/" else self.target + self.entry

        try:
            results = self.parser.run_katana(
                start_url=start_url,
                max_depth=self.max_depth,
                concurrency=self.concurrency,
                timeout=self.timeout,
                session_cookies=self.session_cookies,
            )
        except TimeoutError:
            self.partial = True
            self.status = "PARTIAL"
            results = []

        if not results and self.status == "COMPLETE":
            self.status = "FAILED"

        self._process_results(results)

        asset_hash = compute_asset_fingerprint(
            self.endpoints, self.static_resources, self.headers, self.cookies
        )

        scan_end = time.time_ns() // 1_000_000

        manifest = build_manifest(
            target=self.target, entry=self.entry, scan_begin=scan_begin, scan_end=scan_end,
            status=self.status, partial=self.partial, urls_crawled=self.urls_crawled,
            endpoints=self.endpoints, static_resources=self.static_resources,
            headers=self.headers, cookies=self.cookies, asset_hash=asset_hash,
        )

        logger.debug(
            "crawl_complete  status=%r  urls=%d  endpoints=%d  static=%d  fingerprint=%s  duration_ms=%d",
            self.status, self.urls_crawled, len(self.endpoints), len(self.static_resources),
            asset_hash, scan_end - scan_begin,
        )
        return manifest

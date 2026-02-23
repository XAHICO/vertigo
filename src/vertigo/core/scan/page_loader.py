"""Playwright page lifecycle management."""

import logging
import time
from typing import Dict, Any
from bs4 import BeautifulSoup
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeout
from urllib.parse import urlparse, urlunparse

from .link_extractor import _strip_default_port

logger = logging.getLogger("vertigo.scan.page_loader")


class PageLoader:
    """Manages page loading and content extraction."""

    def __init__(self, mute: bool = False):
        self.mute = mute

    def load_page(self, page: Page, url: str, timeout: int = 10000) -> tuple:
        start_time = time.time()
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            elapsed = time.time() - start_time
            actual_url = page.url
            return response, actual_url, elapsed
        except PlaywrightTimeout:
            elapsed = time.time() - start_time
            raise PlaywrightTimeout(f"Timeout loading {url} after {elapsed:.1f}s")

    def get_normalized_url(self, actual_url: str) -> str:
        actual_parsed = urlparse(actual_url)
        actual_netloc = _strip_default_port(actual_parsed.scheme, actual_parsed.netloc)
        return urlunparse((actual_parsed.scheme, actual_netloc, actual_parsed.path, "", "", ""))

    def analyze_page(self, page: Page, url: str) -> Dict[str, Any]:
        try:
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator=" ", strip=True)
            title = soup.title.string if soup.title else ""
            num_forms   = len(soup.find_all("form"))
            num_scripts = len(soup.find_all("script"))
            num_links   = len(soup.find_all("a"))
            num_inputs  = len(soup.find_all("input"))
            num_buttons = len(soup.find_all(["button", 'input[type="submit"]']))
            num_tables  = len(soup.find_all("table"))
            num_images  = len(soup.find_all("img"))
            try:
                xhr_count = page.evaluate(
                    '() => window.performance ? window.performance.getEntriesByType("xmlhttprequest").length : 0'
                )
            except Exception:
                xhr_count = 0
            try:
                js_errors = page.evaluate('() => window.__jsErrors ? window.__jsErrors.length : 0')
            except Exception:
                js_errors = 0
            dynamic_content_length = len(html)
            return {
                "html": html, "soup": soup, "text": text, "title": title,
                "num_forms": num_forms, "num_scripts": num_scripts, "num_links": num_links,
                "num_inputs": num_inputs, "num_buttons": num_buttons, "num_tables": num_tables,
                "num_images": num_images, "xhr_count": xhr_count, "js_errors": js_errors,
                "dynamic_content_length": dynamic_content_length, "content_length": len(html),
            }
        except Exception as exc:
            logger.debug("page_analysis_error  url=%r  error=%r", url, str(exc))
            return {}

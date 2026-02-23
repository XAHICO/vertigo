"""Same-origin link discovery."""

import logging
from typing import List
from urllib.parse import urlparse, urljoin, urlunparse
from playwright.sync_api import Page

logger = logging.getLogger("vertigo.scan.link_extractor")


def _strip_default_port(scheme: str, netloc: str) -> str:
    """Strip default port from netloc (80 for http, 443 for https)."""
    netloc = netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return netloc


class LinkExtractor:
    """Extract same-origin links from pages."""

    def __init__(self, target: str, mute: bool = False):
        self.target = target
        self.mute = mute
        target_parsed = urlparse(target)
        self.target_netloc = _strip_default_port(target_parsed.scheme, target_parsed.netloc)

    def extract_links(self, page: Page, current_url: str) -> List[str]:
        links = []
        try:
            for elem in page.locator("a[href]").all()[:100]:
                try:
                    href = elem.get_attribute("href")
                    if href:
                        full_url = urljoin(current_url, href)
                        parsed = urlparse(full_url)
                        link_netloc = _strip_default_port(parsed.scheme, parsed.netloc)
                        if link_netloc == self.target_netloc:
                            normalized = urlunparse((parsed.scheme, link_netloc, parsed.path, "", "", ""))
                            links.append(normalized)
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("link_extraction_error  url=%r  error=%r", current_url, str(exc))
        return list(set(links))

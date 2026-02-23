"""
Vertigo public Python API — cloud ML edition.

All ML inference is delegated to the XAHICO cloud service via CloudClient.
No ML model artefacts are stored or read on the client machine.
"""

import logging
from typing import Optional

from .core.auth.context import AuthSessionContext
from .core.auth.authenticator import BrowserAuthenticator
from .core.fingerprint.crawler import ShallowCrawler
from .core.scan import DeepCrawler
from .cloud_client import CloudClient

logger = logging.getLogger("vertigo.api")


def create_default_session(target: str) -> AuthSessionContext:
    return AuthSessionContext(
        cookies=[],
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        storage={"localStorage": {}, "sessionStorage": {}},
        fingerprint="unauthenticated",
        expires=None,
        success=True,
        failure_reason=None,
        target=target,
    )


def authenticate(
    target: str,
    entry: str,
    username: str,
    password: str,
    headless: bool = True,
    silent: bool = True,
    cloud_client: Optional[CloudClient] = None,
) -> AuthSessionContext:
    authenticator = BrowserAuthenticator(
        target=target,
        entry=entry,
        username=username,
        password=password,
        headless=headless,
        mute=silent,
        cloud_client=cloud_client,
    )
    return authenticator.authenticate()


def fingerprint(
    target: str,
    entry: str,
    depth: int = 10,
    limit: int = 10,
    timeout: int = 30,
    concurrency: int = 1,
    session: Optional[AuthSessionContext] = None,
    headless: bool = True,
    silent: bool = True,
    cloud_client: Optional[CloudClient] = None,
) -> dict:
    """
    Capture a fingerprint of a web application.

    Returns a dict with:
    - metadata: scan info, stats, status
    - asset_fingerprint: composite hash
    - resource_hashes: endpoints, static resources, headers, cookies
    """
    if session is None:
        session = create_default_session(target)

    crawler = ShallowCrawler(
        target=target,
        entry=entry,
        max_depth=depth,
        max_urls=limit,
        timeout=timeout,
        concurrency=concurrency,
        mute=silent,
        session=session,
    )
    return crawler.crawl()


def scan(
    target: str,
    entry: str,
    depth: int = 10,
    limit: int = 10,
    timeout: int = 30,
    concurrency: int = 1,
    session: Optional[AuthSessionContext] = None,
    headless: bool = True,
    silent: bool = True,
    cloud_client: Optional[CloudClient] = None,
    sub_depth: int = 0,
) -> dict:
    if session is None:
        session = create_default_session(target)

    crawler = DeepCrawler(
        target=target,
        entry=entry,
        max_depth=depth,
        max_urls=limit,
        timeout=timeout,
        mute=silent,
        headless=headless,
        session=session,
        cloud_client=cloud_client,
        sub_depth=sub_depth,
    )
    return crawler.crawl()

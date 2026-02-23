"""Apply cookies, headers, and storage to browser context."""

import hashlib
import logging
from typing import Optional
from playwright.sync_api import BrowserContext, Page
from .context import AuthSessionContext

logger = logging.getLogger("vertigo.auth.context_builder")


class ContextBuilder:
    """Build and extract browser context with auth session."""

    def __init__(self, target: str, start_url: str, mute: bool = False):
        self.target = target
        self.start_url = start_url
        self.mute = mute

    def extract_session(
        self,
        context: BrowserContext,
        page: Page,
        success: bool,
        failure_reason: Optional[str],
    ) -> AuthSessionContext:
        logger.debug("session_extract_start  target=%r  success=%s", self.target, success)

        cookies = context.cookies()

        headers = {}
        try:
            result = page.evaluate("""
                () => ({ userAgent: navigator.userAgent, language: navigator.language, platform: navigator.platform })
            """)
            headers["User-Agent"] = result.get("userAgent", "")
            headers["Accept-Language"] = result.get("language", "")
        except Exception:
            pass

        storage = {}
        try:
            storage = page.evaluate("""
                () => {
                    const local = {}, session = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i); local[key] = localStorage.getItem(key);
                    }
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i); session[key] = sessionStorage.getItem(key);
                    }
                    return { localStorage: local, sessionStorage: session };
                }
            """)
        except Exception as exc:
            logger.debug("storage_extract_error  error=%r", str(exc))

        cookie_names = sorted([c["name"] for c in cookies])
        fingerprint_data = f"{self.start_url}|{','.join(cookie_names)}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        expires = None
        for cookie in cookies:
            if cookie.get("expires", -1) > 0:
                if expires is None or cookie["expires"] < expires:
                    expires = int(cookie["expires"])

        logger.debug("session_extract_complete  cookies=%d  fingerprint=%s", len(cookies), fingerprint)

        return AuthSessionContext(
            cookies=[{
                "name": c["name"], "value": c["value"], "domain": c["domain"],
                "path": c["path"], "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False), "sameSite": c.get("sameSite", "None"),
            } for c in cookies],
            headers=headers,
            storage=storage,
            fingerprint=fingerprint,
            expires=expires,
            success=success,
            failure_reason=failure_reason,
            target=self.target,
        )

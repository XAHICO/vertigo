"""High-level browser-based authentication system — cloud ML edition."""

import logging
from dataclasses import asdict
from typing import Optional
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeout

from .form_classifier import FormClassifier
from .form_detector import FormDetector
from .orchestrator import Orchestrator
from .success_detector import SuccessDetector
from .context_builder import ContextBuilder, AuthSessionContext
from ...cloud_client import CloudClient

logger = logging.getLogger("vertigo.auth.authenticator")


class BrowserAuthenticator:
    """Main authentication system using real browser context."""

    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        entry: str = "/",
        timeout: int = 30,
        headless: bool = True,
        mute: bool = False,
        cloud_client: Optional[CloudClient] = None,
        # Legacy parameters accepted but ignored
        learning_enabled: bool = True,
        model_dir: Optional[str] = None,
    ):
        self.target, self.entry = self._resolve_target_entry(target, entry)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.headless = headless
        self.mute = mute

        self._cloud = cloud_client
        self.classifier = FormClassifier(cloud_client=cloud_client)

        self.status = "UNKNOWN"
        self.failure_reason = None
        self.successful_form = None

        self.initial_cookies: set = set()
        self.initial_cookie_values: dict = {}

    def _resolve_target_entry(self, target: str, entry: str):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if entry == "/" and parsed.path and parsed.path != "/":
            entry = parsed.path
        if not entry.startswith("/"):
            entry = "/" + entry
        if not entry:
            entry = "/"
        return base, entry

    @property
    def start_url(self) -> str:
        return self.target + "/" if self.entry == "/" else self.target + self.entry

    def _setup_request_hooks(self, page) -> None:
        page.evaluate("""
            () => {
                window.__authRequests = [];
                const originalFetch = window.fetch;
                window.fetch = function(...args) {
                    const url = args[0]; const options = args[1] || {};
                    if (options.method === 'POST' || options.method === 'PUT') {
                        try {
                            const body = options.body;
                            if (body && typeof body === 'string') {
                                const parsed = JSON.parse(body);
                                if (parsed.password || parsed.pass || parsed.pwd) {
                                    window.__authRequests.push({ url, method: options.method || 'POST', payload: Object.keys(parsed), timestamp: Date.now() });
                                }
                            }
                        } catch (e) {}
                    }
                    return originalFetch.apply(this, args);
                };
                const originalOpen = XMLHttpRequest.prototype.open;
                const originalSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function(method, url, ...rest) { this.__url = url; this.__method = method; return originalOpen.apply(this, [method, url, ...rest]); };
                XMLHttpRequest.prototype.send = function(body) {
                    if (this.__method === 'POST' || this.__method === 'PUT') {
                        try { if (body && typeof body === 'string') { const parsed = JSON.parse(body); if (parsed.password || parsed.pass || parsed.pwd) { window.__authRequests.push({ url: this.__url, method: this.__method, payload: Object.keys(parsed), timestamp: Date.now() }); } } } catch (e) {}
                    }
                    return originalSend.apply(this, arguments);
                };
            }
        """)

    def authenticate(self) -> AuthSessionContext:
        logger.debug("auth_start  target=%r  entry=%r  url=%r", self.target, self.entry, self.start_url)

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled"],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            page = context.new_page()

            try:
                logger.debug("auth_navigate  url=%r", self.start_url)
                page.goto(self.start_url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                page.wait_for_timeout(2000)

                initial_cookies_full = context.cookies()
                self.initial_cookies = {c["name"] for c in initial_cookies_full}
                self.initial_cookie_values = {c["name"]: c["value"] for c in initial_cookies_full}

                self._setup_request_hooks(page)

                detector = FormDetector(self.classifier, mute=self.mute)
                forms = detector.discover_forms(page)

                if not forms:
                    logger.debug("auth_no_forms_found")
                    self.status = "NO_FORMS"
                    self.failure_reason = "No login forms found on page"
                    ctx_builder = ContextBuilder(self.target, self.start_url, mute=self.mute)
                    return ctx_builder.extract_session(context, page, False, self.failure_reason)

                logger.debug("auth_forms_found  count=%d", len(forms))

                orchestrator = Orchestrator(self.username, self.password, mute=self.mute)
                login_attempted = False
                for i, form in enumerate(forms[:3]):
                    logger.debug("auth_form_attempt  index=%d  total=%d", i + 1, min(len(forms), 3))
                    if orchestrator.attempt_login(page, form):
                        login_attempted = True
                        self.successful_form = form
                        break

                if not login_attempted:
                    logger.debug("auth_submit_failed  reason=no_form_submitted")
                    self.status = "SUBMIT_FAILED"
                    self.failure_reason = "Could not submit login form"
                    ctx_builder = ContextBuilder(self.target, self.start_url, mute=self.mute)
                    return ctx_builder.extract_session(context, page, False, self.failure_reason)

                success_detector = SuccessDetector(
                    self.initial_cookies, self.initial_cookie_values, mute=self.mute,
                )
                self.status, self.failure_reason = success_detector.detect_auth_state(page, self.start_url)

                if self.successful_form and self._cloud is not None:
                    was_success = self.status == "COMPLETE"
                    logger.debug("auth_sample_submit  success=%s", was_success)
                    self.classifier.learn_from_result(self.successful_form.form_text, was_success)

                ctx_builder = ContextBuilder(self.target, self.start_url, mute=self.mute)
                session = ctx_builder.extract_session(
                    context, page,
                    success=(self.status == "COMPLETE"),
                    failure_reason=self.failure_reason,
                )

                logger.debug("auth_complete  status=%r  failure_reason=%r", self.status, self.failure_reason)
                return session

            except PlaywrightTimeout as exc:
                logger.debug("auth_timeout  error=%r", str(exc))
                self.status = "TIMEOUT"
                self.failure_reason = "Operation timed out"
                ctx_builder = ContextBuilder(self.target, self.start_url, mute=self.mute)
                return ctx_builder.extract_session(context, page, False, self.failure_reason)

            except Exception as exc:
                logger.exception("auth_unexpected_error  error=%r", str(exc))
                self.status = "ERROR"
                self.failure_reason = str(exc)
                ctx_builder = ContextBuilder(self.target, self.start_url, mute=self.mute)
                return ctx_builder.extract_session(context, page, False, self.failure_reason)

            finally:
                browser.close()


def create_session(
    target: str,
    username: str,
    password: str,
    entry: str = "/",
    timeout: int = 30,
    headless: bool = True,
    mute: bool = False,
    cloud_client: Optional[CloudClient] = None,
    learning_enabled: bool = True,
    model_dir: Optional[str] = None,
) -> dict:
    authenticator = BrowserAuthenticator(
        target=target, username=username, password=password,
        entry=entry, timeout=timeout, headless=headless, mute=mute,
        cloud_client=cloud_client,
    )
    session = authenticator.authenticate()
    result = asdict(session)
    result["metadata"] = {
        "target": authenticator.target,
        "entry": authenticator.entry,
        "username": username,
        "status": authenticator.status,
    }
    return result

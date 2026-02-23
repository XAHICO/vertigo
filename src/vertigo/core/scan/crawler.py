"""DeepCrawler orchestration — main scanning engine."""

import hashlib
import json
import logging
import re
import socket
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs, urljoin

from playwright.sync_api import sync_playwright, Page, BrowserContext
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from bs4 import BeautifulSoup

from .throttler import SafetyThrottle
from .link_extractor import _strip_default_port
from .form_extractor import DiscoveredForm
from .js_analyzer import PassiveAPIObserver, DynamicEndpointDiscoverer, DynamicEndpoint, JSCapabilityAnalyzer
from .anomaly_detector import AnomalyDetector
from .page_classifier import PageClassifier, PageType
from .resource_graph import ResourceGraph, ResourceNode, ResourceType
from ..auth.context import AuthSessionContext
from ...cloud_client import CloudClient

logger = logging.getLogger("vertigo.scan.crawler")


@dataclass
class DiscoveredEndpoint:
    """Discovered HTTP endpoint."""
    url: str
    method: str
    params: List[str]
    requires_auth: bool
    response_code: int
    response_type: str
    response_size: int
    response_time: float
    capabilities: List[str]
    page_type: PageType
    anomaly_score: float
    discovery_depth: int
    visited: bool = False
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


class DeepCrawler:
    """Main deep discovery crawler."""

    def __init__(
        self,
        target: str,
        session: AuthSessionContext,
        entry: str = "/",
        max_depth: int = 10,
        max_urls: int = 5000,
        timeout: int = 300,
        headless: bool = True,
        mute: bool = False,
        username: str = None,
        password: str = None,
        login_entry: str = None,
        cloud_client: Optional[CloudClient] = None,
        sub_depth: int = 0,
        # Legacy parameter — accepted but unused
        model_dir: str = None,
    ):
        self.target = self._normalize_target(target)
        self.entry = entry if entry else "/"
        self.session = session
        self.has_auth = bool(session.cookies) or session.fingerprint != "unauthenticated"
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.headless = headless
        self.mute = mute
        self.sub_depth = sub_depth

        self.username = username
        self.password = password
        self.login_entry = login_entry or entry or "/"

        # ML components — wired to cloud client
        self.anomaly_detector = AnomalyDetector(cloud_client=cloud_client)
        self.page_classifier = PageClassifier(cloud_client=cloud_client)
        self.js_analyzer = JSCapabilityAnalyzer()

        # Dynamic endpoint discovery
        self.dynamic_discoverer = DynamicEndpointDiscoverer()
        self.api_observer = PassiveAPIObserver()

        # Safety
        self.safety = SafetyThrottle(max_rpm=60)

        # State
        self.visited: Set[str] = set()
        self.queue: deque = deque()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.seen_endpoint_keys: Set[str] = set()
        self.discovered_forms: List[DiscoveredForm] = []
        self.seen_form_keys: Set[str] = set()
        self.resource_graph = ResourceGraph()

        # Subdomain tracking — populated during link extraction
        self.discovered_subdomains: Set[str] = set()

        self.response_samples: List[Dict] = []

        self.stats = {
            "urls_crawled": 0,
            "endpoints_found": 0,
            "forms_found": 0,
            "apis_discovered": 0,
            "depth_reached": 0,
            "anomalies_detected": 0,
            "dynamic_endpoints_found": 0,
            "static_endpoints_found": 0,
            "transact_calls_detected": 0,
            "endpoint_registry_found": False,
        }

        self.status = "UNKNOWN"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _normalize_target(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _normalize_endpoint_path(path: str) -> str:
        if not path:
            return "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return path

    @staticmethod
    def _resolve_host(host: str) -> str:
        """
        If *host* looks like an IPv4 address, attempt a reverse-DNS lookup and
        return the canonical hostname so subdomain detection works correctly.
        Falls back to the original string on any error.
        """
        try:
            # Quick IPv4 check — four octets of digits
            parts = host.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                name, *_ = socket.gethostbyaddr(host)
                return name.lower()
        except Exception:
            pass
        return host.lower()

    @staticmethod
    def _get_root_domain(host: str) -> str:
        """Return the registrable root domain (last two labels)."""
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else host

    @staticmethod
    def _sanitize_for_json(obj: Any) -> Any:
        """
        Recursively convert any non-JSON-serialisable value (e.g. Enum, bytes,
        dataclass) into a plain Python type so the payload can be json.dumps'd.
        """
        if isinstance(obj, dict):
            return {k: DeepCrawler._sanitize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [DeepCrawler._sanitize_for_json(v) for v in obj]
        if hasattr(obj, "value"):          # Enum
            return obj.value
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        try:
            json.dumps(obj)                # already serialisable
            return obj
        except TypeError:
            return str(obj)

    # ── Session application ───────────────────────────────────────────────────

    def _apply_session(self, context: BrowserContext):
        if not self.session.cookies:
            logger.debug("session_apply  cookies=0")
            return

        target_parsed = urlparse(self.target)
        cookies_to_add = []

        for i, cookie in enumerate(self.session.cookies):
            cookie_copy = cookie.copy()
            if "name" not in cookie_copy or "value" not in cookie_copy:
                logger.debug("cookie_skip  index=%d  reason=missing_name_or_value", i)
                continue
            if "domain" not in cookie_copy and "url" not in cookie_copy:
                cookie_copy["url"] = self.target
            if "domain" in cookie_copy and ":" in cookie_copy["domain"]:
                cookie_copy["domain"] = cookie_copy["domain"].split(":")[0]
            cookies_to_add.append(cookie_copy)

        if cookies_to_add:
            try:
                context.add_cookies(cookies_to_add)
                logger.debug("session_apply  cookies=%d", len(cookies_to_add))
            except Exception as exc:
                logger.debug("session_apply_error  error=%r", str(exc))
                raise

    def _apply_storage(self, page: Page):
        try:
            for key, value in self.session.storage.get("localStorage", {}).items():
                page.evaluate(f"localStorage.setItem({json.dumps(key)}, {json.dumps(value)})")
            for key, value in self.session.storage.get("sessionStorage", {}).items():
                page.evaluate(f"sessionStorage.setItem({json.dumps(key)}, {json.dumps(value)})")
        except Exception as exc:
            logger.debug("storage_apply_error  error=%r", str(exc))

    # ── Auth helpers ──────────────────────────────────────────────────────────

    def _detect_login_page(self, page: Page) -> bool:
        url_lower = page.url.lower()
        title_lower = page.title().lower()

        if any(tok in url_lower for tok in ("login", "signin", "sign-in", "auth")):
            return True
        if any(tok in title_lower for tok in ("login", "sign in", "log in", "signin")):
            return True

        try:
            has_password = page.locator('input[type="password"]').count() > 0
            has_logout = page.locator('a[href*="logout"], a[href*="signout"]').count() > 0
            if has_password and not has_logout:
                return True
        except Exception:
            pass

        return False

    def _authenticate_in_browser(self, page: Page, context: BrowserContext) -> bool:
        logger.debug("browser_auth_attempt  login_entry=%r", self.login_entry)
        login_url = self.target + self.login_entry
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=10000)
            page.wait_for_timeout(1000)
        except Exception as exc:
            logger.debug("browser_auth_nav_error  error=%r", str(exc))
            return False

        username_filled = False
        for selector in [
            'input[name="username"]', 'input[name="user"]',
            'input[name="email"]', 'input[name="login"]',
            'input[name="userid"]', 'input[name="uname"]',
            'input[type="text"]', 'input[type="email"]',
        ]:
            try:
                elem = page.locator(selector).first
                if elem.is_visible(timeout=500):
                    elem.fill(self.username)
                    username_filled = True
                    break
            except Exception:
                continue

        if not username_filled:
            logger.debug("browser_auth_error  reason=username_field_not_found")
            return False

        try:
            page.locator('input[type="password"]').first.fill(self.password)
        except Exception as exc:
            logger.debug("browser_auth_error  reason=password_field_not_found  error=%r", str(exc))
            return False

        submitted = False
        for selector in [
            'input[type="submit"]', 'button[type="submit"]',
            'input[name="Login"]', 'input[name="login"]',
            'button:has-text("Login")', 'button:has-text("Sign in")',
            'button:has-text("Log in")',
        ]:
            try:
                elem = page.locator(selector).first
                if elem.is_visible(timeout=500):
                    elem.click()
                    submitted = True
                    break
            except Exception:
                continue

        if not submitted:
            logger.debug("browser_auth_error  reason=submit_button_not_found")
            return False

        try:
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            page.wait_for_timeout(1000)
        except Exception:
            pass

        if self._detect_login_page(page):
            logger.debug("browser_auth_error  reason=still_on_login_page  url=%r", page.url)
            return False

        logger.debug("browser_auth_success  url=%r", page.url)
        self.has_auth = True
        self.session.fingerprint = hashlib.md5(
            json.dumps(context.cookies(), sort_keys=True).encode()
        ).hexdigest()[:16]
        return True

    # ── Subdomain detection helpers ───────────────────────────────────────────

    def _check_url_for_subdomain(self, url: str, target_host: str, root_domain: str) -> None:
        """If *url* belongs to a sibling/child subdomain, register it."""
        if not url or not url.startswith(("http://", "https://")):
            return
        try:
            parsed = urlparse(url)
            raw_host = parsed.hostname or ""
            link_host = self._resolve_host(raw_host)
            if (
                link_host
                and root_domain
                and link_host != target_host
                and (link_host == root_domain or link_host.endswith("." + root_domain))
                and link_host not in self.discovered_subdomains
            ):
                self.discovered_subdomains.add(link_host)
                logger.debug("subdomain_discovered  host=%r  source=url", link_host)
        except Exception:
            pass

    def _scan_page_for_subdomains(self, page: Page, current_url: str,
                                   target_host: str, root_domain: str) -> None:
        """
        Scan multiple HTML tag/attribute combinations for subdomain references.
        Covers: a[href], script[src], iframe[src], form[action], link[href], img[src].
        Also regex-scans the raw page source to catch inline JS / CSS / text references
        that never appear in DOM attributes.
        """
        selectors = [
            ("a[href]",      "href"),
            ("script[src]",  "src"),
            ("iframe[src]",  "src"),
            ("form[action]", "action"),
            ("link[href]",   "href"),
            ("img[src]",     "src"),
        ]
        for selector, attr in selectors:
            try:
                for elem in page.locator(selector).all()[:50]:
                    try:
                        val = elem.get_attribute(attr)
                        if val:
                            full_url = urljoin(current_url, val)
                            self._check_url_for_subdomain(full_url, target_host, root_domain)
                    except Exception:
                        continue
            except Exception:
                continue

        # Regex fallback — scan the raw HTML for any URL-like token that references
        # a sibling subdomain. This catches inline JS strings, CSS url(), JSON blobs,
        # and any other reference that wouldn't appear in a standard attribute.
        if root_domain:
            try:
                html = page.content()
                # Match protocol-relative and absolute URLs mentioning the root domain
                pattern = re.compile(
                    r"(?:https?:)?//([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
                    + re.escape(root_domain) + r")\b",
                    re.IGNORECASE,
                )
                for m in pattern.finditer(html):
                    candidate = m.group(1).lower()
                    if candidate != target_host:
                        self._check_url_for_subdomain(
                            f"https://{candidate}/", target_host, root_domain
                        )
            except Exception:
                pass

    # ── Link extraction with subdomain detection ──────────────────────────────

    def _extract_links(self, page: Page, current_url: str) -> List[str]:
        """Extract same-origin links; detect subdomains from all tag types as a side-effect."""
        links = []
        target_parsed = urlparse(self.target)
        target_netloc = _strip_default_port(target_parsed.scheme, target_parsed.netloc)
        target_host = self._resolve_host(target_parsed.hostname or "")
        root_domain = self._get_root_domain(target_host)

        # Crawlable links — <a href> only
        try:
            for elem in page.locator("a[href]").all()[:100]:
                try:
                    href = elem.get_attribute("href")
                    if not href:
                        continue
                    full_url = urljoin(current_url, href)
                    parsed = urlparse(full_url)
                    link_netloc = _strip_default_port(parsed.scheme, parsed.netloc)
                    link_host = parsed.hostname or ""

                    if link_netloc == target_netloc:
                        normalized = urlunparse((parsed.scheme, link_netloc, parsed.path, "", "", ""))
                        links.append(normalized)
                    else:
                        # Let the broader scanner handle subdomain detection
                        pass
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("link_extraction_error  url=%r  error=%r", current_url, str(exc))

        # Subdomain detection — scan all relevant tag types
        self._scan_page_for_subdomains(page, current_url, target_host, root_domain)

        return list(set(links))

    # ── Page analysis ─────────────────────────────────────────────────────────

    def _analyze_page(self, page: Page, url: str, depth: int) -> Dict:
        try:
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")

            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator=" ", strip=True)

            title = soup.title.string if soup.title else ""
            num_forms    = len(soup.find_all("form"))
            num_scripts  = len(soup.find_all("script"))
            num_links    = len(soup.find_all("a"))
            num_inputs   = len(soup.find_all("input"))
            num_buttons  = len(soup.find_all(["button", 'input[type="submit"]']))
            num_tables   = len(soup.find_all("table"))
            num_images   = len(soup.find_all("img"))

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

            response_data_ml = {
                "num_forms": num_forms, "num_scripts": num_scripts,
                "num_links": num_links, "num_inputs": num_inputs,
                "num_buttons": num_buttons, "num_tables": num_tables,
                "num_images": num_images, "xhr_count": xhr_count,
                "js_errors": js_errors, "dynamic_content_length": dynamic_content_length,
                "content_length": len(html),
            }

            page_type, confidence = self.page_classifier.classify(text[:2000], url, title, response_data_ml)

            forms = self._extract_forms(soup, url)

            scripts = soup.find_all("script")
            capabilities = []
            for script in scripts[:10]:
                if script.string:
                    js_cap = self.js_analyzer.analyze(script.string)
                    if js_cap.dangerous_functions or js_cap.can_issue_auth_requests:
                        capabilities.append({
                            "dangerous": js_cap.dangerous_functions,
                            "auth_capable": js_cap.can_issue_auth_requests,
                        })

            return {
                "title": title, "text": text[:1000],
                "num_forms": num_forms, "num_scripts": num_scripts,
                "num_links": num_links, "num_inputs": num_inputs,
                "num_buttons": num_buttons, "num_tables": num_tables,
                "num_images": num_images, "xhr_count": xhr_count,
                "js_errors": js_errors, "page_type": page_type,
                "page_type_confidence": confidence, "forms": forms,
                "capabilities": capabilities, "response_data_ml": response_data_ml,
            }

        except Exception as exc:
            logger.debug("page_analysis_error  url=%r  error=%r", url, str(exc))
            return {}

    def _extract_forms(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        forms = []
        for idx, form in enumerate(soup.find_all("form")[:10]):
            try:
                form_id = form.get("id", f"form_{idx}")
                action = form.get("action", url)
                method = form.get("method", "get").upper()
                fields = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    field = {
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "required": inp.has_attr("required"),
                    }
                    if field["name"]:
                        fields.append(field)
                forms.append({
                    "form_id": form_id,
                    "action": urljoin(url, action),
                    "method": method,
                    "fields": fields,
                })
            except Exception:
                continue
        return forms

    # ── URL crawling ──────────────────────────────────────────────────────────

    def _crawl_url(self, page: Page, url: str, depth: int):
        if url in self.visited or depth > self.max_depth:
            logger.debug("url_skip  url=%r  reason=%s",
                         url, "visited" if url in self.visited else "depth_exceeded")
            return

        if len(self.visited) >= self.max_urls:
            logger.debug("url_skip  reason=max_urls_reached  limit=%d", self.max_urls)
            return

        can_request, reason = self.safety.can_make_request("GET")
        if not can_request:
            logger.debug("url_skip  url=%r  reason=%r", url, reason)
            return

        logger.debug("url_crawl  depth=%d/%d  url=%r", depth, self.max_depth, url)

        try:
            start_time = time.time()
            response = page.goto(url, wait_until="domcontentloaded", timeout=10000)
            elapsed = time.time() - start_time

            logger.debug("url_loaded  url=%r  status=%s  elapsed_ms=%.0f",
                         url, response.status if response else "none", elapsed * 1000)

            if self.session.storage and (
                self.session.storage.get("localStorage") or
                self.session.storage.get("sessionStorage")
            ):
                self._apply_storage(page)
                try:
                    page.wait_for_timeout(500)
                except Exception:
                    pass

            self.visited.add(url)
            self.stats["urls_crawled"] += 1
            self.stats["depth_reached"] = max(self.stats["depth_reached"], depth)

            actual_url = page.url
            actual_parsed = urlparse(actual_url)
            actual_netloc = _strip_default_port(actual_parsed.scheme, actual_parsed.netloc)
            actual_normalized = urlunparse((actual_parsed.scheme, actual_netloc, actual_parsed.path, "", "", ""))
            if actual_normalized != url:
                logger.debug("url_redirect  from=%r  to=%r", url, actual_normalized)
                self.visited.add(actual_normalized)

            if not response:
                logger.debug("url_no_response  url=%r", url)
                self.safety.record_error()
                return

            self.safety.record_success()

            response_data = {
                "status_code": response.status,
                "content_length": len(page.content()),
                "response_time": elapsed,
                "headers": response.headers,
                "redirect_count": 0,
                "content_type": response.headers.get("content-type", ""),
            }

            analysis = self._analyze_page(page, actual_normalized, depth)
            response_data.update(analysis)

            captured_requests = self.dynamic_discoverer.get_captured_requests(page)
            if captured_requests:
                logger.debug("network_requests_captured  count=%d  url=%r", len(captured_requests), url)
                # Subdomains often surface in runtime API traffic before any HTML link
                _target_host = self._resolve_host(urlparse(self.target).hostname or "")
                _root_domain = self._get_root_domain(_target_host)
                for _req in captured_requests:
                    self._check_url_for_subdomain(_req.url, _target_host, _root_domain)

            try:
                page_source = page.content()
                static_endpoints = self.dynamic_discoverer.analyze_static_code(page_source, self.target)
                if static_endpoints:
                    logger.debug("static_endpoints_found  count=%d  url=%r", len(static_endpoints), url)
            except Exception as exc:
                logger.debug("static_analysis_error  error=%r", str(exc))

            if self.stats["urls_crawled"] == 1:
                registry = self.dynamic_discoverer.check_endpoint_registry(page, self.target)
                if registry:
                    self.stats["endpoint_registry_found"] = True
                    logger.debug("endpoint_registry_found  count=%d", len(registry.endpoints))

            observed_calls = self.api_observer.collect_observations(page)
            if observed_calls:
                logger.debug("api_calls_observed  count=%d  url=%r", len(observed_calls), url)

            page_type = analysis.get("page_type", PageType.UNKNOWN)
            if page_type in (PageType.DASHBOARD, PageType.ADMIN, PageType.PROFILE) and depth <= 2:
                self.dynamic_discoverer.simulate_user_interactions(page, max_interactions=5)

            if len(self.response_samples) < 100:
                self.response_samples.append(response_data)

            anomaly_score = 0.0
            if self.anomaly_detector.is_trained:
                try:
                    safe_response_data = self._sanitize_for_json(response_data)
                    anomaly_score = self.anomaly_detector.score(safe_response_data)
                    if anomaly_score > 0.7:
                        self.stats["anomalies_detected"] += 1
                        logger.debug("anomaly_detected  score=%.4f  url=%r", anomaly_score, url)
                except Exception as exc:
                    logger.debug("anomaly_score_error  url=%r  error=%r", url, str(exc))

            endpoint_path = actual_parsed.path or "/"
            if actual_parsed.query:
                endpoint_path += "?" + actual_parsed.query
            endpoint_path = self._normalize_endpoint_path(endpoint_path)

            ep_key = f"GET:{endpoint_path}"
            endpoint = DiscoveredEndpoint(
                url=endpoint_path,
                method="GET",
                params=list(parse_qs(actual_parsed.query or "").keys()),
                requires_auth=self.has_auth,
                response_code=response.status,
                response_type=response_data["content_type"],
                response_size=response_data["content_length"],
                response_time=elapsed,
                capabilities=[],
                page_type=analysis.get("page_type", PageType.UNKNOWN),
                anomaly_score=anomaly_score,
                discovery_depth=depth,
                visited=True,
                references=[],
            )

            if ep_key in self.seen_endpoint_keys:
                for i, existing_ep in enumerate(self.discovered_endpoints):
                    if existing_ep.url == endpoint_path and existing_ep.method == "GET":
                        self.discovered_endpoints[i] = endpoint
                        logger.debug("endpoint_updated  path=%r  status=%d", endpoint_path, response.status)
                        break
            else:
                self.seen_endpoint_keys.add(ep_key)
                self.discovered_endpoints.append(endpoint)
                self.stats["endpoints_found"] += 1

            endpoint_node = ResourceNode(
                node_id=f"endpoint:{hashlib.md5(actual_normalized.encode()).hexdigest()[:16]}",
                resource_type=ResourceType.ENDPOINT,
                attributes={
                    "url": actual_normalized,
                    "method": "GET",
                    "page_type": analysis.get("page_type", PageType.UNKNOWN).value,
                    "anomaly_score": anomaly_score,
                },
                discovered_at=int(time.time()),
            )
            self.resource_graph.add_node(endpoint_node)

            for form_data in analysis.get("forms", []):
                form_action = form_data["action"]
                if form_action.startswith("http"):
                    form_action = urlparse(form_action).path or "/"
                form_action = self._normalize_endpoint_path(form_action)
                form_key = f"{form_data['method'].upper()}:{form_action}"
                if form_key in self.seen_form_keys:
                    continue
                self.seen_form_keys.add(form_key)
                form = DiscoveredForm(
                    form_id=form_data["form_id"],
                    url=endpoint_path,
                    action=form_action,
                    method=form_data["method"],
                    fields=form_data["fields"],
                    classification="unknown",
                    requires_auth=self.has_auth,
                )
                self.discovered_forms.append(form)
                self.stats["forms_found"] += 1

            if depth < self.max_depth:
                links = self._extract_links(page, actual_normalized)
                logger.debug("links_extracted  count=%d  url=%r", len(links), actual_normalized)

                link_paths = []
                queued_count = 0
                for link in links:
                    link_parsed = urlparse(link)
                    link_path = self._normalize_endpoint_path(link_parsed.path or "/")
                    link_paths.append(link_path)

                    if link not in self.visited:
                        self.queue.append((link, depth + 1))
                        queued_count += 1

                        lep_key = f"GET:{link_path}"
                        if lep_key not in self.seen_endpoint_keys:
                            self.seen_endpoint_keys.add(lep_key)
                            self.discovered_endpoints.append(DiscoveredEndpoint(
                                url=link_path, method="GET", params=[],
                                requires_auth=self.has_auth, response_code=0,
                                response_type="unknown", response_size=0,
                                response_time=0.0, capabilities=[],
                                page_type=PageType.UNKNOWN, anomaly_score=0.0,
                                discovery_depth=depth + 1, visited=False, references=[],
                            ))
                            self.stats["endpoints_found"] += 1

                endpoint.references = list(set(link_paths))
                logger.debug("urls_queued  count=%d  queue_size=%d", queued_count, len(self.queue))

        except PlaywrightTimeout:
            logger.debug("url_timeout  url=%r", url)
            self.safety.record_error()

        except Exception as exc:
            import traceback
            logger.debug("url_error  url=%r  error=%r\n%s", url, str(exc), traceback.format_exc())
            self.safety.record_error()

    # ── Subdomain scanning ────────────────────────────────────────────────────

    def _crawl_subdomains(self, page: Page):
        """Perform a shallow crawl of each discovered subdomain up to self.sub_depth levels."""
        if not self.discovered_subdomains or self.sub_depth == 0:
            return

        target_parsed = urlparse(self.target)
        scheme = target_parsed.scheme

        for subdomain_host in sorted(self.discovered_subdomains):
            sub_origin = f"{scheme}://{subdomain_host}"
            start_url = sub_origin + "/"
            logger.debug("subdomain_crawl_start  host=%r  max_depth=%d", subdomain_host, self.sub_depth)

            sub_queue: deque = deque([(start_url, 0)])
            sub_visited: Set[str] = set()

            while sub_queue:
                sub_url, sub_depth_val = sub_queue.popleft()
                if sub_url in sub_visited or sub_depth_val > self.sub_depth:
                    continue
                if len(self.visited) + len(sub_visited) >= self.max_urls:
                    logger.debug("subdomain_crawl_limit  host=%r", subdomain_host)
                    break

                sub_visited.add(sub_url)

                can_request, reason = self.safety.can_make_request("GET")
                if not can_request:
                    logger.debug("subdomain_url_skip  url=%r  reason=%r", sub_url, reason)
                    continue

                logger.debug("subdomain_url_crawl  depth=%d/%d  url=%r",
                             sub_depth_val, self.sub_depth, sub_url)

                try:
                    start_time = time.time()
                    response = page.goto(sub_url, wait_until="domcontentloaded", timeout=10000)
                    elapsed = time.time() - start_time

                    if not response:
                        continue

                    self.safety.record_success()

                    actual_url = page.url
                    actual_parsed = urlparse(actual_url)
                    actual_netloc = _strip_default_port(actual_parsed.scheme, actual_parsed.netloc)
                    actual_normalized = urlunparse(
                        (actual_parsed.scheme, actual_netloc, actual_parsed.path, "", "", "")
                    )

                    endpoint_path = self._normalize_endpoint_path(actual_parsed.path or "/")
                    # Prefix with subdomain to keep endpoints namespaced
                    full_endpoint_key = f"GET:{actual_netloc}{endpoint_path}"
                    if full_endpoint_key not in self.seen_endpoint_keys:
                        self.seen_endpoint_keys.add(full_endpoint_key)
                        self.stats["endpoints_found"] += 1

                    logger.debug("subdomain_url_loaded  url=%r  status=%d", sub_url, response.status)

                    # Extract links if not at max sub-depth
                    if sub_depth_val < self.sub_depth:
                        sub_netloc = _strip_default_port(actual_parsed.scheme, actual_parsed.netloc)
                        try:
                            for elem in page.locator("a[href]").all()[:50]:
                                try:
                                    href = elem.get_attribute("href")
                                    if not href:
                                        continue
                                    full = urljoin(actual_normalized, href)
                                    parsed = urlparse(full)
                                    if _strip_default_port(parsed.scheme, parsed.netloc) == sub_netloc:
                                        link_norm = urlunparse((parsed.scheme, sub_netloc, parsed.path, "", "", ""))
                                        if link_norm not in sub_visited:
                                            sub_queue.append((link_norm, sub_depth_val + 1))
                                except Exception:
                                    continue
                        except Exception as exc:
                            logger.debug("subdomain_link_error  error=%r", str(exc))

                except PlaywrightTimeout:
                    logger.debug("subdomain_timeout  url=%r", sub_url)
                    self.safety.record_error()
                except Exception as exc:
                    logger.debug("subdomain_error  url=%r  error=%r", sub_url, str(exc))
                    self.safety.record_error()

            logger.debug("subdomain_crawl_complete  host=%r  urls_visited=%d", subdomain_host, len(sub_visited))

    # ── Main entry point ──────────────────────────────────────────────────────

    def crawl(self) -> Dict:
        scan_begin = time.time_ns() // 1_000_000

        logger.debug(
            "crawl_start  target=%r  entry=%r  auth=%s  depth=%d  urls=%d  timeout=%ds  sub_depth=%d",
            self.target, self.entry, self.has_auth, self.max_depth, self.max_urls,
            self.timeout, self.sub_depth,
        )

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)

            extra_headers = {
                k: v for k, v in self.session.headers.items()
                if k.lower() != "user-agent"
            }

            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=self.session.headers.get("User-Agent", "Mozilla/5.0"),
                extra_http_headers=extra_headers if extra_headers else None,
            )

            self._apply_session(context)
            page = context.new_page()

            logger.debug("instrumentation_start")
            self.dynamic_discoverer.instrument_page(page)
            self.api_observer.install_interceptors(page)
            self._apply_storage(page)

            try:
                start_url = self.target + self.entry if self.entry != "/" else self.target + "/"

                if self.has_auth or (self.username and self.password):
                    logger.debug("session_validation_start  url=%r", start_url)
                    try:
                        page.goto(start_url, wait_until="domcontentloaded", timeout=10000)
                        page.wait_for_timeout(500)
                    except Exception as exc:
                        logger.debug("session_validation_nav_error  error=%r", str(exc))

                    if self._detect_login_page(page):
                        logger.debug("session_expired  attempting_browser_auth=%s",
                                     bool(self.username and self.password))
                        if self.username and self.password:
                            auth_ok = self._authenticate_in_browser(page, context)
                            if not auth_ok:
                                logger.debug("browser_auth_failed  proceeding=unauthenticated")
                                self.has_auth = False
                                self.session.fingerprint = "unauthenticated"
                    else:
                        logger.debug("session_valid")

                self.queue.append((start_url, 0))
                start_time = time.time()

                while self.queue and not self.safety.paused:
                    if time.time() - start_time > self.timeout:
                        logger.debug("crawl_timeout  elapsed_s=%.1f", time.time() - start_time)
                        self.status = "PARTIAL"
                        break

                    url, depth = self.queue.popleft()
                    logger.debug("crawl_queue_pop  queue=%d  url=%r  depth=%d",
                                 len(self.queue), url, depth)
                    try:
                        self._crawl_url(page, url, depth)
                    except Exception as exc:
                        import traceback
                        logger.debug("crawl_loop_error  url=%r  error=%r\n%s",
                                     url, str(exc), traceback.format_exc())
                        self.safety.record_error()

                if not self.queue:
                    logger.debug("crawl_bfs_complete  reason=queue_empty")
                elif self.safety.paused:
                    logger.debug("crawl_bfs_complete  reason=safety_paused  errors=%d",
                                 self.safety.error_count)

                if len(self.response_samples) >= 10 and not self.anomaly_detector.is_trained:
                    logger.debug("anomaly_detector_training  samples=%d", len(self.response_samples))
                    self.anomaly_detector.fit(self.response_samples)

                if self.safety.paused:
                    self.status = "BLOCKED"
                elif len(self.visited) >= self.max_urls:
                    self.status = "PARTIAL"
                elif self.status == "UNKNOWN":
                    self.status = "COMPLETE"

                logger.debug("dynamic_endpoint_analysis_start")
                dynamic_endpoints = self.dynamic_discoverer.analyze_captured_endpoints(self.target)

                static_count = sum(
                    1 for e in self.dynamic_discoverer.dynamic_endpoints
                    if e.discovered_via == "static_analysis"
                )
                runtime_count = len(self.dynamic_discoverer.dynamic_endpoints) - static_count
                self.stats["dynamic_endpoints_found"] = runtime_count
                self.stats["static_endpoints_found"] = static_count
                self.stats["transact_calls_detected"] = len(self.dynamic_discoverer.transact_calls)

                # Subdomain scanning (only if sub_depth > 0)
                if self.sub_depth > 0 and self.discovered_subdomains:
                    logger.debug("subdomain_scan_start  count=%d", len(self.discovered_subdomains))
                    self._crawl_subdomains(page)

            finally:
                browser.close()

        scan_end = time.time_ns() // 1_000_000

        # Asset fingerprint
        all_endpoint_hashes = []
        for ep in self.discovered_endpoints:
            all_endpoint_hashes.append(hashlib.sha256(f"{ep.method} {ep.url}".encode()).hexdigest())
        for form in self.discovered_forms:
            all_endpoint_hashes.append(hashlib.sha256(f"{form.method} {form.action}".encode()).hexdigest())
        for dyn in self.dynamic_discoverer.dynamic_endpoints:
            all_endpoint_hashes.append(hashlib.sha256(f"{dyn.method} {dyn.url}".encode()).hexdigest())
        combined = "|".join(sorted(all_endpoint_hashes)) if all_endpoint_hashes else ""
        asset_fingerprint = hashlib.sha256(combined.encode()).hexdigest()

        endpoints_data = []
        for e in self.discovered_endpoints:
            ep_dict = asdict(e)
            ep_dict["page_type"] = e.page_type.value if isinstance(e.page_type, PageType) else e.page_type
            endpoints_data.append(ep_dict)

        report = {
            "metadata": {
                "target": self.target,
                "entry": self.entry,
                "session_fingerprint": self.session.fingerprint,
                "authenticated": self.has_auth,
                "scan_begin": scan_begin,
                "scan_end": scan_end,
                "status": self.status,
                "stats": self.stats,
            },
            "asset_fingerprint": asset_fingerprint,
            "endpoints": endpoints_data,
            "forms": [asdict(f) for f in self.discovered_forms],
            "dynamic_endpoints": [asdict(e) for e in self.dynamic_discoverer.dynamic_endpoints],
            "subdomains": {
                "discovered": sorted(self.discovered_subdomains),
                "scanned": sorted(self.discovered_subdomains) if self.sub_depth > 0 else [],
                "sub_depth": self.sub_depth,
            },
            "summary": {
                "total_urls": len(self.visited),
                "total_endpoints": len(self.discovered_endpoints),
                "total_forms": len(self.discovered_forms),
                "dynamic_endpoints": len(self.dynamic_discoverer.dynamic_endpoints),
                "dynamic_endpoints_runtime": self.stats["dynamic_endpoints_found"],
                "dynamic_endpoints_static": self.stats["static_endpoints_found"],
                "anomalies": self.stats["anomalies_detected"],
                "depth_reached": self.stats["depth_reached"],
                "subdomains_discovered": len(self.discovered_subdomains),
                "subdomains_scanned": len(self.discovered_subdomains) if self.sub_depth > 0 else 0,
            },
        }

        logger.debug(
            "crawl_complete  status=%r  urls=%d  endpoints=%d  forms=%d  anomalies=%d  "
            "subdomains=%d  fingerprint=%s  duration_ms=%d",
            self.status, self.stats["urls_crawled"], self.stats["endpoints_found"],
            self.stats["forms_found"], self.stats["anomalies_detected"],
            len(self.discovered_subdomains), asset_fingerprint,
            scan_end - scan_begin,
        )

        return report

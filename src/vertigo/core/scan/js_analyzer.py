"""JavaScript endpoint and capability analysis."""

import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs
from playwright.sync_api import Page

logger = logging.getLogger("vertigo.scan.js_analyzer")


def _try_parse_json(body: Optional[str]) -> Optional[Any]:
    """Parse *body* as JSON; return None if empty, not valid JSON, or not a string."""
    if not body or not body.strip():
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


@dataclass
class ObservedAPICall:
    url: str
    method: str
    headers: Dict[str, str]
    has_body: bool
    has_auth: bool
    timestamp: int
    origin: str
    normalized_path: str
    classification: str
    confidence: float = 1.0


@dataclass
class DynamicEndpoint:
    url: str
    method: str
    headers: Dict[str, str]
    payload: Optional[Dict[str, Any]]
    response_type: str
    response_size: int
    requires_auth: bool
    auth_token: Optional[str]
    discovered_via: str
    triggered_by: str
    timestamp: int


@dataclass
class EndpointRegistry:
    registry_url: str
    endpoints: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    is_ndjson: bool
    discovered_at: int


@dataclass
class NetworkRequest:
    url: str
    method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: Optional[str]
    timing: float
    initiated_by: str


FETCH_INTERCEPTOR_JS = """
(function () {
  const originalFetch = window.fetch;
  window.__observedAPICalls = window.__observedAPICalls || [];
  window.fetch = async function (input, init = {}) {
    try {
      const method = (init.method || "GET").toUpperCase();
      const url = typeof input === "string" ? input : input.url;
      const headers = {};
      let hasAuth = false;
      if (init.headers) {
        for (const [k, v] of Object.entries(init.headers)) {
          if (k.toLowerCase() === "authorization" || k.toLowerCase().includes("token")) {
            headers[k] = "<redacted>"; hasAuth = true;
          } else { headers[k] = v; }
        }
      }
      window.__observedAPICalls.push({ method, url, headers, hasBody: !!init.body, hasAuth, timestamp: Date.now(), origin: "fetch" });
    } catch (e) {}
    return originalFetch.apply(this, arguments);
  };
})();
"""

XHR_INTERCEPTOR_JS = """
(function () {
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  const setRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  window.__observedAPICalls = window.__observedAPICalls || [];
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    this.__requestHeaders = this.__requestHeaders || {};
    if (name.toLowerCase() === "authorization" || name.toLowerCase().includes("token")) {
      this.__requestHeaders[name] = "<redacted>"; this.__hasAuth = true;
    } else { this.__requestHeaders[name] = value; }
    return setRequestHeader.apply(this, arguments);
  };
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__method = method; this.__url = url; this.__requestHeaders = {}; this.__hasAuth = false;
    return open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    window.__observedAPICalls.push({ method: this.__method, url: this.__url, headers: this.__requestHeaders || {}, hasBody: !!body, hasAuth: this.__hasAuth || false, timestamp: Date.now(), origin: "xhr" });
    return send.apply(this, arguments);
  };
})();
"""


class PassiveAPIObserver:
    """Passive API observation — intercepts fetch/XHR without generating traffic."""

    def __init__(self):
        self.observed_calls: List[ObservedAPICall] = []
        self.unique_endpoints: Dict[str, ObservedAPICall] = {}

    def install_interceptors(self, page: Page):
        try:
            page.evaluate(FETCH_INTERCEPTOR_JS)
            page.evaluate(XHR_INTERCEPTOR_JS)
            logger.debug("api_interceptors_installed")
        except Exception as exc:
            logger.debug("api_interceptors_error  error=%r", str(exc))

    def collect_observations(self, page: Page) -> List[ObservedAPICall]:
        try:
            raw_calls = page.evaluate("window.__observedAPICalls || []")
            new_calls = []
            for call in raw_calls:
                normalized = self._normalize_url(call["url"])
                classification = self._classify_method(call["method"])
                observed = ObservedAPICall(
                    url=call["url"], method=call["method"],
                    headers=call.get("headers", {}), has_body=call.get("hasBody", False),
                    has_auth=call.get("hasAuth", False),
                    timestamp=call.get("timestamp", int(time.time() * 1000)),
                    origin=call.get("origin", "unknown"),
                    normalized_path=normalized, classification=classification, confidence=1.0,
                )
                new_calls.append(observed)
                self.observed_calls.append(observed)
                key = f"{call['method']}:{normalized}"
                if key not in self.unique_endpoints:
                    self.unique_endpoints[key] = observed
            page.evaluate("window.__observedAPICalls = []")
            if new_calls:
                logger.debug("api_calls_collected  count=%d", len(new_calls))
            return new_calls
        except Exception as exc:
            logger.debug("api_collection_error  error=%r", str(exc))
            return []

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path
            path = re.sub(r'/\d+(/|$)', r'/{id}\1', path)
            path = re.sub(r'/[a-f0-9]{24,}(/|$)', r'/{id}\1', path, flags=re.IGNORECASE)
            path = re.sub(
                r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(/|$)',
                r'/{id}\1', path, flags=re.IGNORECASE,
            )
            return path
        except Exception:
            return url

    def _classify_method(self, method: str) -> str:
        return "mutative" if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} else "read_only"

    def get_summary(self) -> Dict[str, Any]:
        endpoints_by_type: Dict[str, list] = defaultdict(list)
        for key, call in self.unique_endpoints.items():
            endpoints_by_type[call.classification].append({
                "method": call.method, "normalized_path": call.normalized_path,
                "requires_auth": call.has_auth, "discovered_via": "passive_runtime",
                "confidence": call.confidence, "origin": call.origin,
            })
        return {
            "total_calls_observed": len(self.observed_calls),
            "unique_endpoints": len(self.unique_endpoints),
            "read_only_endpoints": len(endpoints_by_type["read_only"]),
            "mutative_endpoints": len(endpoints_by_type["mutative"]),
            "endpoints": dict(endpoints_by_type),
        }


class DynamicEndpointDiscoverer:
    """Discovers runtime-generated API endpoints via JS instrumentation."""

    def __init__(self):
        self.captured_requests: List[NetworkRequest] = []
        self.dynamic_endpoints: List[DynamicEndpoint] = []
        self.endpoint_registry: Optional[EndpointRegistry] = None
        self.transact_calls: List[Dict[str, Any]] = []
        self.route_captured_requests: List[Dict[str, Any]] = []
        self.session_headers: Dict[str, str] = {}

    def instrument_page(self, page: Page):
        logger.debug("route_interception_setup")
        self.route_captured_requests = []

        def handle_route(route):
            request = route.request
            self.route_captured_requests.append({
                "url": request.url, "method": request.method,
                "headers": request.headers, "post_data": request.post_data,
                "timestamp": int(time.time() * 1000),
            })
            route.continue_()

        try:
            page.route("**/*", handle_route)
            logger.debug("route_interception_active")
        except Exception as exc:
            logger.debug("route_interception_error  error=%r", str(exc))

        self._inject_js_instrumentation(page)

    def _inject_js_instrumentation(self, page: Page):
        instrumentation_script = """
        (function() {
            window.__oracleNetworkCapture__ = { requests: [], transactCalls: [], authTokens: new Set() };
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const startTime = performance.now();
                let url = args[0]; let options = args[1] || {};
                const requestInfo = { url: typeof url === 'string' ? url : url.url, method: options.method || 'GET', headers: options.headers || {}, body: options.body, initiatedBy: 'fetch', timestamp: Date.now() };
                if (options.headers) {
                    const authHeader = options.headers['Authorization'] || options.headers['authorization'];
                    if (authHeader) window.__oracleNetworkCapture__.authTokens.add(authHeader);
                }
                return originalFetch.apply(this, args).then(response => {
                    const endTime = performance.now();
                    const clonedResponse = response.clone();
                    clonedResponse.text().then(body => {
                        window.__oracleNetworkCapture__.requests.push({ ...requestInfo, responseStatus: response.status, responseHeaders: Object.fromEntries(response.headers.entries()), responseBody: body.substring(0, 10000), timing: endTime - startTime });
                    }).catch(() => {
                        window.__oracleNetworkCapture__.requests.push({ ...requestInfo, responseStatus: response.status, responseHeaders: Object.fromEntries(response.headers.entries()), timing: endTime - startTime });
                    });
                    return response;
                });
            };
            const originalXHROpen = XMLHttpRequest.prototype.open;
            const originalXHRSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                this.__oracleXHR__ = { method, url, startTime: performance.now(), timestamp: Date.now() };
                return originalXHROpen.apply(this, [method, url, ...rest]);
            };
            XMLHttpRequest.prototype.send = function(body) {
                const xhr = this;
                if (this.__oracleXHR__) this.__oracleXHR__.body = body;
                xhr.addEventListener('load', function() {
                    if (xhr.__oracleXHR__) {
                        window.__oracleNetworkCapture__.requests.push({ url: xhr.__oracleXHR__.url, method: xhr.__oracleXHR__.method, body: xhr.__oracleXHR__.body, initiatedBy: 'xhr', timestamp: xhr.__oracleXHR__.timestamp, responseStatus: xhr.status, responseHeaders: xhr.getAllResponseHeaders(), responseBody: xhr.responseText ? xhr.responseText.substring(0, 10000) : null, timing: performance.now() - xhr.__oracleXHR__.startTime });
                    }
                });
                return originalXHRSend.apply(this, arguments);
            };
            const checkForTransact = () => {
                if (typeof window.__GWXWebApplication__ !== 'undefined' && typeof window.__GWXWebApplication__.transact === 'function') {
                    const originalTransact = window.__GWXWebApplication__.transact;
                    window.__GWXWebApplication__.transact = function(...args) {
                        try { window.__oracleNetworkCapture__.transactCalls.push({ args: [args[0], args[1], args[2]], timestamp: Date.now() }); } catch(e) {}
                        return originalTransact.apply(this, args);
                    };
                } else { setTimeout(checkForTransact, 100); }
            };
            checkForTransact();
        })();
        """
        try:
            page.add_init_script(instrumentation_script)
            logger.debug("js_instrumentation_injected")
        except Exception as exc:
            logger.debug("js_instrumentation_error  error=%r", str(exc))

    @staticmethod
    def _parse_response_headers(raw: Any) -> Dict[str, str]:
        """
        Normalise *raw* to a plain ``{str: str}`` dict regardless of whether it
        arrived as an already-parsed dict (from fetch/route) or as the raw
        ``getAllResponseHeaders()`` multiline string returned by XHR.
        """
        if isinstance(raw, dict):
            return {str(k).lower(): str(v) for k, v in raw.items()}
        if isinstance(raw, str):
            result: Dict[str, str] = {}
            for line in raw.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    result[k.strip().lower()] = v.strip()
            return result
        return {}

    def get_captured_requests(self, page: Page) -> List[NetworkRequest]:
        captured = []
        for req_data in self.route_captured_requests:
            try:
                captured.append(NetworkRequest(
                    url=req_data.get("url", ""), method=req_data.get("method", "GET"),
                    request_headers=req_data.get("headers", {}),
                    request_body=req_data.get("post_data"), response_status=0,
                    response_headers={}, response_body=None, timing=0, initiated_by="route",
                ))
            except Exception as exc:
                logger.debug("route_request_parse_error  error=%r", str(exc))

        route_count = len(self.route_captured_requests)
        self.route_captured_requests = []

        try:
            capture_data = page.evaluate("() => window.__oracleNetworkCapture__")
            if capture_data:
                for req in capture_data.get("requests", []):
                    try:
                        captured.append(NetworkRequest(
                            url=req.get("url", ""), method=req.get("method", "GET"),
                            request_headers=req.get("headers", {}),
                            request_body=req.get("body"), response_status=req.get("responseStatus", 0),
                            response_headers=self._parse_response_headers(req.get("responseHeaders", {})),
                            response_body=req.get("responseBody"), timing=req.get("timing", 0),
                            initiated_by=req.get("initiatedBy", "js"),
                        ))
                    except Exception as exc:
                        logger.debug("js_request_parse_error  error=%r", str(exc))
                self.transact_calls.extend(capture_data.get("transactCalls", []))
        except Exception as exc:
            logger.debug("js_capture_retrieve_error  error=%r", str(exc))

        self.captured_requests.extend(captured)
        if captured:
            logger.debug("requests_captured  total=%d  route=%d  js=%d",
                         len(captured), route_count, len(captured) - route_count)
        return captured

    def check_endpoint_registry(self, page: Page, base_url: str) -> Optional[EndpointRegistry]:
        registry_paths = ["/api/v1/schema", "/.well-known/api-endpoints", "/api/v1/exports"]
        for path in registry_paths:
            try:
                registry_url = urljoin(base_url, path)
                logger.debug("registry_check  url=%r", registry_url)
                response = page.request.get(registry_url)
                if response.status != 200:
                    continue
                content_type = response.headers.get("content-type", "")
                body = response.text()
                is_ndjson = "ndjson" in content_type or "x-ndjson" in content_type
                endpoints = []
                metadata = {}
                if is_ndjson:
                    lines = body.strip().split("\n")
                    if lines:
                        try:
                            metadata = json.loads(lines[0])
                            for line in lines[1:]:
                                if line.strip():
                                    endpoints.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.debug("registry_ndjson_parse_error  url=%r", registry_url)
                else:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            metadata = data.get("metadata", {})
                            endpoints = data.get("endpoints", data.get("apis", []))
                        elif isinstance(data, list):
                            endpoints = data
                    except json.JSONDecodeError:
                        logger.debug("registry_json_parse_error  url=%r", registry_url)
                if endpoints:
                    logger.debug("registry_found  url=%r  count=%d", registry_url, len(endpoints))
                    self.endpoint_registry = EndpointRegistry(
                        registry_url=registry_url, endpoints=endpoints,
                        metadata=metadata, is_ndjson=is_ndjson, discovered_at=int(time.time()),
                    )
                    return self.endpoint_registry
            except Exception as exc:
                logger.debug("registry_check_error  path=%r  error=%r", path, str(exc))
        return None

    def simulate_user_interactions(self, page: Page, max_interactions: int = 10):
        logger.debug("user_interaction_simulation_start  max=%d", max_interactions)
        interactions = 0
        try:
            buttons = page.locator('button, [role="button"], .btn, [type="submit"]').all()
            logger.debug("clickable_elements_found  count=%d", len(buttons))
            for button in buttons[:max_interactions]:
                try:
                    if interactions >= max_interactions:
                        break
                    if button.is_visible():
                        try:
                            text = button.inner_text()[:50]
                        except Exception:
                            text = "unknown"
                        logger.debug("button_click  text=%r", text)
                        button.click(timeout=2000)
                        page.wait_for_timeout(150)
                        interactions += 1
                except Exception:
                    pass
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(300)
            except Exception:
                pass
            try:
                toggles = page.locator('[role="button"][aria-expanded="false"]').all()
                for toggle in toggles[:5]:
                    try:
                        toggle.click(timeout=1000)
                        page.wait_for_timeout(100)
                    except Exception:
                        pass
            except Exception:
                pass
            logger.debug("user_interaction_simulation_complete  interactions=%d", interactions)
        except Exception as exc:
            logger.debug("user_interaction_error  error=%r", str(exc))

    def analyze_captured_endpoints(self, target: str = None) -> List[DynamicEndpoint]:
        endpoint_map = {}
        for req in self.captured_requests:
            parsed = urlparse(req.url)
            if any(parsed.path.endswith(ext) for ext in
                   [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2"]):
                continue
            is_api = any([
                "/api/" in parsed.path, "/v1/" in parsed.path, "/v2/" in parsed.path,
                "/graphql" in parsed.path,
                self._parse_response_headers(req.response_headers).get("content-type", "").startswith("application/json"),
                self._parse_response_headers(req.response_headers).get("content-type", "").startswith("application/ndjson"),
            ])
            if not is_api and req.method == "GET":
                continue
            normalized_path = self._normalize_runtime_path(parsed.path)
            endpoint_key = f"{req.method}:{normalized_path}"
            if endpoint_key not in endpoint_map:
                requires_auth = any([
                    "authorization" in req.request_headers,
                    "Authorization" in req.request_headers,
                    "bearer" in str(req.request_headers).lower(),
                    req.response_status == 401,
                ])
                auth_token = None
                for header_name in ["authorization", "Authorization"]:
                    if header_name in req.request_headers:
                        auth_token = req.request_headers[header_name]
                        break
                normalized_headers = (
                    self._normalize_headers(req.request_headers, target)
                    if target and req.request_headers else (req.request_headers or {})
                )
                endpoint = DynamicEndpoint(
                    url=normalized_path, method=req.method, headers=normalized_headers,
                    payload=_try_parse_json(req.request_body),
                    response_type=self._parse_response_headers(req.response_headers).get("content-type", "unknown"),
                    response_size=len(req.response_body) if req.response_body else 0,
                    requires_auth=requires_auth, auth_token=auth_token,
                    discovered_via=req.initiated_by, triggered_by="runtime",
                    timestamp=int(time.time()),
                )
                endpoint_map[endpoint_key] = endpoint
                self.dynamic_endpoints.append(endpoint)
        logger.debug("dynamic_endpoints_analyzed  count=%d", len(self.dynamic_endpoints))
        if self.dynamic_endpoints:
            self._resolve_static_endpoints()
        return self.dynamic_endpoints

    def _normalize_runtime_path(self, path: str) -> str:
        if not path or not isinstance(path, str):
            return "/"
        try:
            parts = path.split("/")
            normalized_parts = []
            for part in parts:
                if not part:
                    normalized_parts.append(part)
                    continue
                if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part, re.IGNORECASE):
                    normalized_parts.append("{*}")
                elif re.match(r"^\d+$", part):
                    normalized_parts.append("{*}")
                elif re.match(r"^[a-zA-Z0-9]{16,}$", part):
                    normalized_parts.append("{*}")
                else:
                    normalized_parts.append(part)
            return "/".join(normalized_parts)
        except Exception:
            return path

    def _normalize_headers(self, headers: dict, target: str) -> dict:
        if not headers or not isinstance(headers, dict):
            return {}
        normalized = headers.copy()
        for referer_key in ["referer", "Referer"]:
            if referer_key in normalized:
                referer_value = normalized.get(referer_key)
                if not referer_value or not isinstance(referer_value, str):
                    continue
                try:
                    target_parsed = urlparse(target)
                    referer_parsed = urlparse(referer_value)
                    if referer_parsed.netloc == target_parsed.netloc:
                        normalized[referer_key] = referer_parsed.path if referer_parsed.path else "/"
                except Exception:
                    continue
        return normalized

    def _resolve_static_endpoints(self):
        if not self.dynamic_endpoints:
            return
        runtime_baseline = self._build_runtime_baseline()
        if not runtime_baseline["prefixes"]:
            logger.debug("static_resolution_skipped  reason=no_runtime_baseline")
            return
        static_eps = [e for e in self.dynamic_endpoints if e.discovered_via == "static_analysis"]
        runtime_eps = [e for e in self.dynamic_endpoints if e.discovered_via != "static_analysis"]
        reference_eps = runtime_baseline["runtime_endpoints"]
        if not static_eps:
            return
        logger.debug("static_resolution_start  static=%d  reference=%d", len(static_eps), len(reference_eps))
        is_wildcard_only = all("*" in e.url for e in reference_eps)
        resolved_count = 0
        unresolved_count = 0
        for static_ep in static_eps:
            if self._path_looks_complete(static_ep.url):
                static_ep.triggered_by = "complete:1.00"
                resolved_count += 1
                continue
            resolution = self._resolve_single_endpoint(static_ep, runtime_baseline, reference_eps)
            confidence_threshold = 0.5 if is_wildcard_only else 0.7
            if resolution and resolution["confidence"] >= confidence_threshold:
                static_ep.url = resolution["resolved_path"]
                static_ep.triggered_by = f"resolved:{resolution['confidence']:.2f}"
                resolved_count += 1
            else:
                static_ep.triggered_by = "unresolved:low_confidence"
                unresolved_count += 1
        self.dynamic_endpoints = [
            e for e in self.dynamic_endpoints
            if not (e.discovered_via == "static_analysis" and "unresolved" in e.triggered_by)
        ]
        self._deduplicate_endpoints()
        logger.debug("static_resolution_complete  resolved=%d  unresolved=%d",
                     resolved_count, unresolved_count)

    def _deduplicate_endpoints(self):
        seen = {}
        deduplicated = []
        priority_order = {"route": 1, "fetch": 2, "xhr": 3, "transact": 4, "static_analysis": 5}
        for endpoint in self.dynamic_endpoints:
            key = f"{endpoint.method}:{endpoint.url}"
            if key not in seen:
                seen[key] = endpoint
                deduplicated.append(endpoint)
            else:
                existing = seen[key]
                if priority_order.get(endpoint.discovered_via, 999) < priority_order.get(existing.discovered_via, 999):
                    idx = deduplicated.index(existing)
                    deduplicated[idx] = endpoint
                    seen[key] = endpoint
        removed = len(self.dynamic_endpoints) - len(deduplicated)
        if removed:
            logger.debug("endpoints_deduplicated  removed=%d", removed)
        self.dynamic_endpoints = deduplicated

    def _build_runtime_baseline(self) -> dict:
        runtime_eps = [e for e in self.dynamic_endpoints if e.discovered_via != "static_analysis"]
        static_eps = [e for e in self.dynamic_endpoints if e.discovered_via == "static_analysis"]
        if runtime_eps:
            return self._build_baseline_from_endpoints(runtime_eps)
        if static_eps:
            complete_static = [e for e in static_eps if self._path_looks_complete(e.url)]
            if complete_static:
                logger.debug("baseline_from_static  count=%d", len(complete_static))
                return self._build_baseline_from_endpoints(complete_static)
        return {"prefixes": [], "path_patterns": [], "method_patterns": {}}

    def _build_baseline_from_endpoints(self, endpoints: list) -> dict:
        all_paths = [ep.url for ep in endpoints]
        common_prefix = self._find_common_api_prefix(all_paths)
        path_segments = [self._tokenize_path(ep.url) for ep in endpoints]
        method_paths: Dict[str, list] = {}
        for ep in endpoints:
            method_paths.setdefault(ep.method, []).append(ep.url)
        prefixes = [common_prefix] if common_prefix else []
        return {"prefixes": prefixes, "path_patterns": path_segments,
                "method_patterns": method_paths, "runtime_endpoints": endpoints}

    def _find_common_api_prefix(self, paths: list) -> str:
        if not paths:
            return ""
        api_paths = [p for p in paths if any(
            m in p.lower() for m in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]
        )]
        if not api_paths:
            return ""
        prefix_counts: Dict[str, int] = {}
        for path in api_paths:
            parts = path.split("/")
            for i in range(1, min(len(parts), 5)):
                prefix = "/".join(parts[:i + 1])
                if prefix and len(prefix) > 1:
                    prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
        if not prefix_counts:
            return ""
        threshold = max(len(api_paths) * 0.5, 2)
        significant = [p for p, c in prefix_counts.items() if c >= threshold]
        if not significant:
            most_common = max(prefix_counts.items(), key=lambda x: x[1])
            return most_common[0] if most_common[1] >= 2 else ""
        significant.sort(key=len, reverse=True)
        return significant[0]

    def _tokenize_path(self, path: str) -> list:
        if not path:
            return []
        tokens = []
        for seg in path.split("/"):
            if not seg:
                tokens.append("")
            elif seg == "{*}" or (seg.startswith("{") and seg.endswith("}")):
                tokens.append("{var}")
            elif re.match(r"^\d+$", seg):
                tokens.append("{var}")
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", seg, re.IGNORECASE):
                tokens.append("{var}")
            else:
                tokens.append(seg)
        return tokens

    def _resolve_single_endpoint(self, static_ep: DynamicEndpoint, baseline: dict, runtime_eps: list) -> Optional[dict]:
        static_path = self._canonicalize_path(static_ep.url)
        static_method = static_ep.method
        if self._path_looks_complete(static_path):
            return self._validate_complete_path(static_path, static_method, runtime_eps)
        if self._is_ui_route(static_path):
            logger.debug("ui_route_skipped  path=%r", static_path)
            return None
        static_tokens = self._tokenize_path(static_path)
        best_resolution = None
        best_confidence = 0.0
        for prefix in baseline["prefixes"]:
            candidate_path = self._construct_candidate_path(prefix, static_path)
            if not self._is_valid_candidate(candidate_path):
                continue
            candidate_tokens = self._tokenize_path(candidate_path)
            for runtime_ep in runtime_eps:
                runtime_tokens = self._tokenize_path(runtime_ep.url)
                if "*" in runtime_ep.url:
                    wildcard_prefix = runtime_ep.url.split("*")[0].rstrip("/")
                    if candidate_path.startswith(wildcard_prefix + "/"):
                        confidence = 0.9 + (0.1 if static_method == runtime_ep.method else 0.0)
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_resolution = {"original_static_path": static_path, "resolved_path": candidate_path,
                                               "method": static_method, "confidence": confidence,
                                               "evidence": [runtime_ep.url], "matched_prefix": prefix}
                        continue
                sim_score = self._compute_structural_similarity(candidate_tokens, runtime_tokens)
                if sim_score == 0:
                    continue
                method_bonus = 0.2 if static_method == runtime_ep.method else (0.1 if runtime_ep.method in ["GET", "POST"] else 0.0)
                prefix_confidence = min(baseline["prefixes"].count(prefix) / max(len(runtime_eps), 1), 0.3)
                confidence = min(sim_score * 0.5 + method_bonus + prefix_confidence, 1.0)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_resolution = {"original_static_path": static_path, "resolved_path": candidate_path,
                                       "method": static_method, "confidence": confidence,
                                       "evidence": [runtime_ep.url], "matched_prefix": prefix}
        return best_resolution

    def _canonicalize_path(self, path: str) -> str:
        if not path:
            return "/"
        path = "/" + path.lstrip("/")
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        parts = path.split("/")
        deduplicated = []
        prev = None
        for part in parts:
            if part != prev or part == "":
                deduplicated.append(part)
            prev = part
        result = "/".join(deduplicated)
        if "/api/v1" in result and result.count("/api/v1") > 1:
            first_idx = result.find("/api/v1")
            second_idx = result.find("/api/v1", first_idx + 7)
            if second_idx > 0:
                before_dup = result[first_idx:second_idx]
                after_dup = result[second_idx + 7:].lstrip("/")
                result = before_dup + ("/" + after_dup if after_dup else "")
        elif "/api/" in result and result.count("/api/") > 1:
            parts2 = result.split("/api/")
            if len(parts2) > 2:
                cleaned = [p.strip("/") for p in parts2[1:] if p.strip("/")]
                result = "/api/" + "/".join(cleaned)
        return result

    def _path_looks_complete(self, path: str) -> bool:
        if not path:
            return False
        complete_prefixes = ["/api/v1/", "/api/v2/", "/api/v3/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/api/"]
        return any(path.startswith(p) or p in path[:20] for p in complete_prefixes)

    def _is_ui_route(self, path: str) -> bool:
        if not path:
            return False
        ui_routes = ["/dashboard", "/admin", "/settings", "/profile", "/account",
                     "/login", "/logout", "/register", "/upgrade", "/billing",
                     "/payment", "/home", "/about", "/contact", "/help", "/support", "/", "/index"]
        if path in ui_routes:
            return True
        if path.startswith("/") and not any(api in path for api in ["/api/", "/v1/", "/v2/", "/graphql"]):
            root_segment = path.split("/")[1] if len(path.split("/")) > 1 else ""
            if root_segment in [r.lstrip("/") for r in ui_routes]:
                return True
        return False

    def _construct_candidate_path(self, prefix: str, static_path: str) -> str:
        static_clean = static_path.lstrip("/")
        candidate = (prefix + "/" + static_clean) if not prefix.endswith("/") else (prefix + static_clean)
        return self._canonicalize_path(candidate)

    def _is_valid_candidate(self, path: str) -> bool:
        if not path:
            return False
        if "/api/v1/" in path and path.count("/api/v1/") > 1:
            return False
        if "/api/" in path and path.count("/api/") > 1:
            return False
        if "*.**" in path or "/*.**" in path:
            return False
        ui_segments = ["dashboard", "upgrade", "admin", "settings", "profile", "login", "logout"]
        if "/api/" in path and any(s in path.split("/") for s in ui_segments):
            return False
        return True

    def _validate_complete_path(self, path: str, method: str, runtime_eps: list) -> Optional[dict]:
        path_tokens = self._tokenize_path(path)
        best_confidence = 0.0
        best_match = None
        for runtime_ep in runtime_eps:
            sim_score = self._compute_structural_similarity(path_tokens, self._tokenize_path(runtime_ep.url))
            if sim_score > 0.8:
                confidence = min(sim_score * 0.7 + (0.2 if method == runtime_ep.method else 0.1), 1.0)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {"original_static_path": path, "resolved_path": path, "method": method,
                                  "confidence": confidence, "evidence": [runtime_ep.url], "matched_prefix": "complete"}
        return best_match

    def _compute_structural_similarity(self, tokens1: list, tokens2: list) -> float:
        if not tokens1 or not tokens2:
            return 0.0
        len1, len2 = len(tokens1), len(tokens2)
        if abs(len1 - len2) > 2:
            return 0.0
        arity_score = 1.0 - (abs(len1 - len2) / max(len1, len2))
        min_len = min(len1, len2)
        matching_literals = 0
        for i in range(min_len):
            tok1, tok2 = tokens1[i], tokens2[i]
            if tok1 == tok2 and tok1 not in ("", "{var}"):
                matching_literals += 1
            elif tok1 == "{var}" and tok2 == "{var}":
                matching_literals += 0.5
        if min_len == 0:
            return 0.0
        literal_score = matching_literals / min_len
        return min(literal_score * 0.5 + arity_score * 0.3 + (min_len / min_len) * 0.2, 1.0)

    def analyze_static_code(self, page_source: str, base_url: str) -> List[DynamicEndpoint]:
        logger.debug("static_code_analysis_start")
        static_endpoints = []
        endpoints_found: set = set()
        patterns = [
            (r"fetch\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "fetch"),
            (r"axios\.get\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "axios.get"),
            (r"axios\.post\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "axios.post"),
            (r"axios\.put\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "axios.put"),
            (r"axios\.delete\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "axios.delete"),
            (r"axios\.patch\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "axios.patch"),
            (r"\.open\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"`]([^'\"` ]+)['\"`]", "xhr"),
            (r"\$\.get\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "jquery.get"),
            (r"\$\.post\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "jquery.post"),
            (r"\.transact\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,", "transact"),
            (r"['\"`](/api/[^'\"` \)]+)['\"`]", "url_string"),
            (r"['\"`](/v\d+/[^'\"` \)]+)['\"`]", "url_string"),
        ]
        for pattern_tuple in patterns:
            pattern, source = pattern_tuple[0], pattern_tuple[1]
            for match in re.finditer(pattern, page_source, re.IGNORECASE):
                method = "GET"
                path = None
                if source == "xhr":
                    method = match.group(1).upper()
                    path = match.group(2)
                elif source == "transact":
                    method = match.group(1).upper()
                    path = match.group(2)
                elif source.startswith("axios."):
                    method = source.split(".")[1].upper()
                    path = match.group(1)
                elif source.startswith("jquery."):
                    method = "POST" if source == "jquery.post" else "GET"
                    path = match.group(1)
                else:
                    path = match.group(1)
                if not path or not self._looks_like_api_endpoint(path):
                    continue
                clean_path = re.sub(r"\$\{[^}]+\}", lambda m: "{" + m.group(0)[2:-1] + "}", path)
                generalized_path = re.sub(r"\{[^}]+\}", "{*}", clean_path)
                generalized_path = self._canonicalize_path(generalized_path)
                if not self._is_valid_static_endpoint(generalized_path):
                    continue
                endpoint_key = f"{method}:{generalized_path}"
                if endpoint_key not in endpoints_found:
                    endpoints_found.add(endpoint_key)
                    endpoint = DynamicEndpoint(
                        url=generalized_path, method=method, headers={}, payload=None,
                        response_type="application/json", response_size=0,
                        requires_auth=True, auth_token=None,
                        discovered_via="static_analysis", triggered_by=source,
                        timestamp=int(time.time()),
                    )
                    static_endpoints.append(endpoint)
                    logger.debug("static_endpoint_found  method=%s  path=%r  source=%s",
                                 method, generalized_path, source)
        logger.debug("static_code_analysis_complete  found=%d", len(static_endpoints))
        existing_keys = {
            f"{e.method}:{urlparse(e.url).path if e.url.startswith('http') else e.url}"
            for e in self.dynamic_endpoints
        }
        for endpoint in static_endpoints:
            key = f"{endpoint.method}:{endpoint.url}"
            if key not in existing_keys:
                self.dynamic_endpoints.append(endpoint)
                existing_keys.add(key)
        return static_endpoints

    def _looks_like_api_endpoint(self, path: str) -> bool:
        if not (path.startswith("/") or path.startswith("http")):
            return False
        if any(path.endswith(ext) for ext in [".js", ".css", ".html", ".png", ".jpg", ".gif",
                                               ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico"]):
            return False
        api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/data/"]
        if any(ind in path.lower() for ind in api_indicators):
            return True
        resource_indicators = ["network", "session", "asset", "resource", "task",
                                "user", "auth", "login", "context", "issue"]
        if any(ind in path.lower() for ind in resource_indicators):
            return True
        ui_only = ["/dashboard", "/upgrade", "/admin", "/settings", "/profile", "/home", "/about"]
        if path in ui_only:
            return False
        if path.startswith("/") and len(path.split("/")) > 2:
            return True
        return False

    def _is_valid_static_endpoint(self, path: str) -> bool:
        if not path or len(path) < 2:
            return False
        if not path.startswith("/"):
            return False
        return True


# ── JS Capability Analyser ────────────────────────────────────────────────────

@dataclass
class JSCapability:
    can_read_cookies: bool
    can_write_storage: bool
    can_issue_auth_requests: bool
    can_construct_dynamic_urls: bool
    can_download_blobs: bool
    dangerous_functions: List[str]


class JSCapabilityAnalyzer:
    DANGEROUS_PATTERNS = {
        "eval": r"\beval\s*\(",
        "innerHTML": r"\.innerHTML\s*=",
        "document.write": r"document\.write\s*\(",
        "Function constructor": r"new\s+Function\s*\(",
        "setTimeout string": r"setTimeout\s*\(\s*[\"']",
    }
    CAPABILITY_PATTERNS = {
        "read_cookies": r"document\.cookie",
        "write_storage": r"localStorage\.setItem|sessionStorage\.setItem",
        "auth_requests": r"Authorization|Bearer|X-CSRF-Token",
        "dynamic_urls": r"location\.href\s*=|window\.location",
        "blob_download": r"Blob|createObjectURL|download",
    }

    def analyze(self, js_code: str) -> JSCapability:
        dangerous = [
            name for name, pattern in self.DANGEROUS_PATTERNS.items()
            if re.search(pattern, js_code, re.IGNORECASE)
        ]
        return JSCapability(
            can_read_cookies=bool(re.search(self.CAPABILITY_PATTERNS["read_cookies"], js_code)),
            can_write_storage=bool(re.search(self.CAPABILITY_PATTERNS["write_storage"], js_code)),
            can_issue_auth_requests=bool(re.search(self.CAPABILITY_PATTERNS["auth_requests"], js_code)),
            can_construct_dynamic_urls=bool(re.search(self.CAPABILITY_PATTERNS["dynamic_urls"], js_code)),
            can_download_blobs=bool(re.search(self.CAPABILITY_PATTERNS["blob_download"], js_code)),
            dangerous_functions=dangerous,
        )

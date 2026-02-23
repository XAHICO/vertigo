"""Login success/failure detection logic."""

import logging
import re
from typing import Tuple, Optional, Set
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import Page

logger = logging.getLogger("vertigo.auth.success_detector")


class SuccessDetector:
    AUTH_COOKIE_PATTERNS = [
        r".*session.*", r".*token.*", r".*auth.*", r".*sid.*",
        r".*jwt.*", r".*access.*", r".*refresh.*", r".*login.*",
    ]
    CAPTCHA_PATTERNS = ["g-recaptcha", "h-captcha", "cf-turnstile", "recaptcha", "hcaptcha", "turnstile"]
    BLOCKAGE_INDICATORS = ["rate limit", "too many attempts", "blocked", "banned", "suspended", "access denied", "ip blocked"]
    MFA_INDICATORS = ["two factor", "2fa", "two-factor", "authentication code", "verification code",
                      "authenticator", "sms code", "email code", "security code", "enter code"]

    def __init__(self, initial_cookies: Set[str], initial_cookie_values: dict, mute: bool = False):
        self.initial_cookies = initial_cookies
        self.initial_cookie_values = initial_cookie_values
        self.mute = mute

    def _is_auth_cookie(self, name: str) -> bool:
        name_lower = name.lower()
        return any(re.match(p, name_lower) for p in self.AUTH_COOKIE_PATTERNS)

    def detect_auth_state(self, page: Page, initial_url: str) -> Tuple[str, Optional[str]]:
        logger.debug("auth_state_detection_start  initial_url=%r", initial_url)
        try:
            page.wait_for_timeout(2000)
        except Exception:
            pass

        current_url = page.url
        page_content = ""
        try:
            page_content = page.content().lower()
        except Exception:
            pass

        visible_text = ""
        try:
            visible_text = page.locator("body").inner_text(timeout=5000).lower()
        except Exception:
            pass

        # CAPTCHA check
        captcha_detected = False
        try:
            for pattern in self.CAPTCHA_PATTERNS:
                if page.locator(f'[class*="{pattern}"], [id*="{pattern}"], iframe[src*="{pattern}"]').count() > 0:
                    captcha_detected = True
                    logger.debug("captcha_detected  pattern=%r", pattern)
                    break
        except Exception:
            pass
        if captcha_detected:
            return "CAPTCHA", "CAPTCHA verification required"

        for indicator in self.BLOCKAGE_INDICATORS:
            if indicator in visible_text or indicator in page_content:
                logger.debug("blockage_detected  indicator=%r", indicator)
                return "BLOCKED", f"Blockage indicator found: {indicator}"

        for indicator in self.MFA_INDICATORS:
            if indicator in visible_text:
                logger.debug("mfa_detected  indicator=%r", indicator)
                return "MFA_REQUIRED", f"Multi-factor authentication required: {indicator}"

        score = 0
        score_breakdown = []

        parsed_url = urlparse(current_url)
        query_params = parse_qs(parsed_url.query)
        failure_param_names = ["error", "err", "incorrect", "invalid", "fail", "failed",
                               "failure", "denied", "deny", "reject", "rejected", "wrong", "bad"]
        failure_values = ["true", "1", "yes", "y"]
        success_param_names = ["success", "logged_in", "loggedin", "authenticated", "auth_ok", "welcome", "redirect", "continue"]

        for param_name, param_values in query_params.items():
            param_name_lower = param_name.lower()
            for failure_pattern in failure_param_names:
                if failure_pattern in param_name_lower:
                    param_value = param_values[0] if param_values else ""
                    if not param_value or param_value.lower() in failure_values:
                        logger.debug("url_failure_indicator  param=%r  value=%r", param_name, param_value)
                        return "FAILED", f"URL indicates failure: ?{param_name}={param_value}"
                    if param_value.lower() not in ["false", "0", "no", "n"]:
                        logger.debug("url_failure_indicator  param=%r  value=%r", param_name, param_value)
                        return "FAILED", f"URL indicates failure: ?{param_name}={param_value}"

        url_success_indicator = False
        for param_name, param_values in query_params.items():
            for success_pattern in success_param_names:
                if success_pattern in param_name.lower():
                    param_value = param_values[0] if param_values else ""
                    if not param_value or param_value.lower() in ["true", "1", "yes", "y"]:
                        url_success_indicator = True
                        logger.debug("url_success_indicator  param=%r", param_name)
                        break

        url_changed = current_url != initial_url
        if url_changed:
            initial_path = initial_url.split("?")[0].rstrip("/")
            current_path = current_url.split("?")[0].rstrip("/")
            if initial_path != current_path:
                score += 20
                score_breakdown.append(f"+20 (url_path_changed  from={initial_path!r}  to={current_path!r})")
                logger.debug("url_path_changed  from=%r  to=%r", initial_path, current_path)
            elif url_success_indicator:
                score += 15
                score_breakdown.append("+15 (url_success_indicator)")
            else:
                score_breakdown.append("+0 (url_params_changed_ambiguous)")
        else:
            score -= 10
            score_breakdown.append("-10 (url_unchanged)")
            logger.debug("url_unchanged  url=%r", current_url)

        strong_success_keywords = ["logout", "sign out", "logged in as"]
        ultra_strong_keywords = ["logout", "sign out"]
        strong_keyword_found = False
        ultra_strong_found = False
        for indicator in strong_success_keywords:
            if indicator in visible_text:
                if indicator in ultra_strong_keywords:
                    score += 40
                    score_breakdown.append(f"+40 (ultra_strong_keyword={indicator!r})")
                    ultra_strong_found = True
                else:
                    score += 30
                    score_breakdown.append(f"+30 (strong_keyword={indicator!r})")
                strong_keyword_found = True
                logger.debug("success_keyword_found  keyword=%r  ultra=%s", indicator, indicator in ultra_strong_keywords)
                break

        if not strong_keyword_found:
            for indicator in ["welcome", "profile", "account", "settings"]:
                if indicator in visible_text:
                    score += 10
                    score_breakdown.append(f"+10 (weak_keyword={indicator!r})")
                    logger.debug("weak_success_keyword  keyword=%r", indicator)
                    break

        if "vulnerabilities" in visible_text or "dvwa security" in visible_text:
            score += 25
            score_breakdown.append("+25 (dvwa_success_indicator)")

        new_cookies = page.context.cookies()
        current_auth_cookies = [c for c in new_cookies if self._is_auth_cookie(c["name"])]
        cookie_changed = False
        new_cookie_names = []
        changed_cookie_names = []
        for new_cookie in current_auth_cookies:
            if new_cookie["name"] not in self.initial_cookies:
                cookie_changed = True
                new_cookie_names.append(new_cookie["name"])
        for new_cookie in current_auth_cookies:
            if new_cookie["name"] in self.initial_cookie_values:
                if self.initial_cookie_values[new_cookie["name"]] != new_cookie["value"]:
                    cookie_changed = True
                    changed_cookie_names.append(new_cookie["name"])
        if cookie_changed:
            score += 25
            parts = []
            if new_cookie_names:
                parts.append(f"new={new_cookie_names}")
            if changed_cookie_names:
                parts.append(f"changed={changed_cookie_names}")
            score_breakdown.append(f"+25 (auth_cookies  {' '.join(parts)})")
            logger.debug("auth_cookies_changed  new=%r  changed=%r", new_cookie_names, changed_cookie_names)

        login_form_present = False
        try:
            pwd_fields = page.locator('input[type="password"]').count()
            if pwd_fields == 0:
                score += 20
                score_breakdown.append("+20 (login_form_disappeared)")
                logger.debug("login_form_disappeared")
            else:
                login_form_present = True
                score -= 25
                score_breakdown.append(f"-25 (login_form_still_present  count={pwd_fields})")
                logger.debug("login_form_still_present  password_fields=%d", pwd_fields)
        except Exception:
            pass

        failure_patterns = [
            "login failed", "authentication failed", "sign in failed",
            "incorrect password", "invalid password", "wrong password",
            "incorrect username", "invalid username", "invalid credentials",
            "login incorrect", "access denied", "login denied",
            "username or password is incorrect", "invalid email or password",
        ]
        failure_found = False
        for pattern in failure_patterns:
            if pattern in visible_text:
                score -= 40
                score_breakdown.append(f"-40 (failure_message={pattern!r})")
                failure_found = True
                logger.debug("explicit_failure_indicator  pattern=%r", pattern)
                break

        if not failure_found:
            for keyword in ["error logging in", "failed to log in", "could not log in",
                            "please try again", "login error", "authentication error"]:
                if keyword in visible_text:
                    score -= 30
                    score_breakdown.append(f"-30 (error_keyword={keyword!r})")
                    logger.debug("error_keyword_detected  keyword=%r", keyword)
                    break

        logger.debug("score_breakdown  %s  total=%d", "  ".join(score_breakdown), score)

        has_cookie_signal = cookie_changed
        has_url_path_change = url_changed and initial_url.split("?")[0] != current_url.split("?")[0]
        has_strong_keyword = strong_keyword_found
        has_form_disappeared = not login_form_present
        signal_types = sum([has_cookie_signal, has_url_path_change, has_strong_keyword, has_form_disappeared])

        if ultra_strong_found and has_form_disappeared:
            logger.debug("auth_result  status=COMPLETE  reason=ultra_strong_keyword_and_form_disappeared")
            return "COMPLETE", None

        if score >= 60 and signal_types >= 2:
            logger.debug("auth_result  status=COMPLETE  score=%d  signal_types=%d", score, signal_types)
            return "COMPLETE", None
        elif score >= 50 and signal_types >= 3:
            logger.debug("auth_result  status=COMPLETE  score=%d  signal_types=%d", score, signal_types)
            return "COMPLETE", None
        elif score >= 45 and has_cookie_signal and (has_url_path_change or has_strong_keyword):
            logger.debug("auth_result  status=COMPLETE  score=%d  cookies_with_strong_signal=True", score)
            return "COMPLETE", None
        elif score >= 25:
            logger.debug("auth_result  status=PARTIAL  score=%d  signal_types=%d", score, signal_types)
            return "PARTIAL", f"Inconclusive (score: {score}). Some success indicators present but not definitive."
        else:
            logger.debug("auth_result  status=FAILED  score=%d", score)
            if failure_found:
                for pattern in failure_patterns:
                    if pattern in visible_text:
                        return "FAILED", f"Authentication failed: {pattern}"
            if login_form_present and not url_changed:
                return "FAILED", "Login form still present and no navigation occurred"
            if score < 0:
                return "FAILED", f"Negative indicators detected (score: {score})"
            return "FAILED", f"Insufficient success indicators (score: {score})"

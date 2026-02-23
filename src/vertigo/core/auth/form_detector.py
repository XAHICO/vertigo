"""DOM + ML login form discovery."""

import logging
from typing import List
from dataclasses import dataclass
from playwright.sync_api import Page

logger = logging.getLogger("vertigo.auth.form_detector")


@dataclass
class CandidateForm:
    root_selector: str
    username_fields: List[str]
    password_field: str
    submit_triggers: List[str]
    form_text: str
    confidence: float


class FormDetector:
    """Discover potential login forms via DOM analysis."""

    def __init__(self, classifier, mute: bool = False):
        self.classifier = classifier
        self.mute = mute

    def _extract_form_features(self, page: Page, form_info: dict) -> str:
        features = []
        for field in form_info.get("username_fields", []):
            try:
                label = page.locator(f'label[for="{field}"]').inner_text(timeout=1000)
                features.append(label.lower())
            except Exception:
                pass
            try:
                placeholder = page.locator(field).get_attribute("placeholder", timeout=1000)
                if placeholder:
                    features.append(placeholder.lower())
            except Exception:
                pass
        pwd_field = form_info.get("password_field")
        if pwd_field:
            try:
                pwd_label = page.locator(f'label[for="{pwd_field}"]').inner_text(timeout=1000)
                features.append(pwd_label.lower())
            except Exception:
                pass
        for trigger in form_info.get("submit_triggers", []):
            try:
                btn_text = page.locator(trigger).inner_text(timeout=1000)
                features.append(btn_text.lower())
            except Exception:
                pass
        try:
            root = form_info.get("root_selector", "body")
            nearby_text = page.locator(root).inner_text(timeout=2000)
            features.append(nearby_text[:200].lower())
        except Exception:
            pass
        return " ".join(features)

    def discover_forms(self, page: Page) -> List[CandidateForm]:
        logger.debug("form_discovery_start")
        candidates = []

        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        page.wait_for_timeout(2000)

        login_triggers = [
            'a:has-text("Login")', 'a:has-text("Log in")', 'a:has-text("Sign in")',
            'button:has-text("Login"):not([type="submit"])',
            'button:has-text("Log in"):not([type="submit"])',
            'button:has-text("Sign in"):not([type="submit"])',
            '[class*="login" i][role="button"]:not(input):not([type="submit"])',
            '[id*="login" i][role="button"]:not(input):not([type="submit"])',
        ]

        for trigger_sel in login_triggers:
            try:
                trigger_count = page.locator(trigger_sel).count()
                if trigger_count > 0:
                    logger.debug("login_trigger_found  selector=%r", trigger_sel)
                    for i in range(min(trigger_count, 3)):
                        try:
                            btn = page.locator(trigger_sel).nth(i)
                            if btn.is_visible(timeout=1000):
                                elem_type = btn.evaluate("el => el.tagName.toLowerCase() + ':' + (el.type || 'none')")
                                if "submit" not in elem_type.lower():
                                    logger.debug("login_trigger_click  index=%d  type=%r", i, elem_type)
                                    btn.click(timeout=3000)
                                    page.wait_for_timeout(2000)
                                    break
                        except Exception:
                            continue
                    break
            except Exception:
                continue

        password_selectors = [
            'input[type="password"]', 'input[autocomplete="current-password"]',
            'input[name*="password" i]', 'input[name*="pass" i]',
            'input[id*="password" i]', 'input[id*="pass" i]',
            'input[data-testid*="password" i]', 'input[data-test-name*="password" i]',
        ]

        try:
            all_password_inputs = []
            for selector in password_selectors:
                try:
                    inputs = page.locator(selector).all()
                    if inputs:
                        logger.debug("password_selector_match  selector=%r  count=%d", selector, len(inputs))
                    all_password_inputs.extend(inputs)
                except Exception:
                    pass

            seen = set()
            password_inputs = []
            for inp in all_password_inputs:
                try:
                    handle = inp.element_handle()
                    if handle and handle not in seen:
                        seen.add(handle)
                        password_inputs.append(inp)
                except Exception:
                    pass

            logger.debug("password_inputs_found  count=%d", len(password_inputs))

            for pwd_input in password_inputs:
                try:
                    form_elem = pwd_input.evaluate("""
                        (elem) => {
                            let form = elem.closest('form');
                            if (!form) { form = elem.closest('div[role="form"]') || elem.closest('div[class*="form"]') || elem.closest('div'); }
                            return { selector: form.tagName + (form.id ? '#' + form.id : '') + (form.className ? '.' + form.className.split(' ')[0] : ''), html: form.innerHTML };
                        }
                    """)
                    root_selector = form_elem["selector"]

                    username_selectors_list = [
                        f'{root_selector} input[type="text"]', f'{root_selector} input[type="email"]',
                        f'{root_selector} input[name*="user" i]', f'{root_selector} input[name*="email" i]',
                        f'{root_selector} input[name*="login" i]',
                        f'{root_selector} input[autocomplete="username"]',
                        f'{root_selector} input[autocomplete="email"]',
                        f'{root_selector} input[id*="user" i]', f'{root_selector} input[id*="email" i]',
                        f'{root_selector} input[data-testid*="user" i]',
                        f'{root_selector} input[data-testid*="email" i]',
                    ]

                    username_candidates = []
                    for sel in username_selectors_list:
                        try:
                            username_candidates.extend(page.locator(sel).all())
                        except Exception:
                            pass

                    seen_users = set()
                    unique_username_candidates = []
                    for user_input in username_candidates:
                        try:
                            handle = user_input.element_handle()
                            if handle and handle not in seen_users:
                                seen_users.add(handle)
                                unique_username_candidates.append(user_input)
                        except Exception:
                            pass

                    username_selectors = []
                    for user_input in unique_username_candidates[:5]:
                        try:
                            selector = user_input.evaluate("""
                                (elem) => {
                                    if (elem.id) return '#' + elem.id;
                                    if (elem.name) return '[name="' + elem.name + '"]';
                                    if (elem.getAttribute('data-testid')) return '[data-testid="' + elem.getAttribute('data-testid') + '"]';
                                    if (elem.className) return '.' + elem.className.split(' ')[0];
                                    return '';
                                }
                            """)
                            if selector:
                                username_selectors.append(selector)
                        except Exception:
                            pass

                    pwd_selector = pwd_input.evaluate("""
                        (elem) => {
                            if (elem.id) return '#' + elem.id;
                            if (elem.name) return '[name="' + elem.name + '"]';
                            if (elem.getAttribute('data-testid')) return '[data-testid="' + elem.getAttribute('data-testid') + '"]';
                            if (elem.className) return '.' + elem.className.split(' ')[0];
                            return '[type="password"]';
                        }
                    """)

                    submit_triggers = []
                    submit_selector_list = [
                        f'{root_selector} button[type="submit"]', f'{root_selector} input[type="submit"]',
                        f'{root_selector} button', f'{root_selector} [role="button"]',
                        f'{root_selector} a[role="button"]',
                    ]
                    submit_candidates = []
                    for sel in submit_selector_list:
                        try:
                            submit_candidates.extend(page.locator(sel).all())
                        except Exception:
                            pass

                    seen_submits = set()
                    for submit in submit_candidates[:5]:
                        try:
                            handle = submit.element_handle()
                            if handle and handle not in seen_submits:
                                seen_submits.add(handle)
                                selector = submit.evaluate("""
                                    (elem) => {
                                        if (elem.id) return '#' + elem.id;
                                        if (elem.getAttribute('data-testid')) return '[data-testid="' + elem.getAttribute('data-testid') + '"]';
                                        if (elem.name) return elem.tagName.toLowerCase() + '[name="' + elem.name + '"]';
                                        if (elem.type && elem.type !== 'text' && elem.type !== 'password') return elem.tagName.toLowerCase() + '[type="' + elem.type + '"]';
                                        if (elem.className) return '.' + elem.className.split(' ')[0];
                                        return elem.tagName.toLowerCase() + '[type="' + (elem.type || 'button') + '"]';
                                    }
                                """)
                                if selector:
                                    submit_triggers.append(selector)
                        except Exception:
                            pass

                    if not submit_triggers:
                        submit_triggers = ['button[type="submit"]', 'input[type="submit"]']

                    form_info = {
                        "root_selector": root_selector,
                        "username_fields": username_selectors,
                        "password_field": pwd_selector,
                        "submit_triggers": submit_triggers,
                    }

                    form_text = self._extract_form_features(page, form_info)
                    is_login, confidence = self.classifier.classify(form_text)

                    logger.debug("form_classified  is_login=%s  confidence=%.2f  text_len=%d",
                                 is_login, confidence, len(form_text))

                    has_username = bool(username_selectors)
                    has_password = bool(pwd_selector)
                    has_submit = bool(submit_triggers)

                    accept_form = False
                    reason = ""
                    if is_login and confidence > 0.3:
                        accept_form = True
                        reason = "ml_confident"
                    elif has_username and has_password and has_submit:
                        accept_form = True
                        reason = "all_components_present"
                    elif has_password and has_submit:
                        accept_form = True
                        reason = "password_and_submit_present"

                    if accept_form:
                        candidates.append(CandidateForm(
                            root_selector=root_selector,
                            username_fields=username_selectors,
                            password_field=pwd_selector,
                            submit_triggers=submit_triggers,
                            form_text=form_text,
                            confidence=confidence,
                        ))
                        logger.debug("form_accepted  reason=%r", reason)
                    else:
                        logger.debug("form_rejected  reason=ml_negative_and_missing_components")

                except Exception as exc:
                    logger.debug("form_process_error  error=%r", str(exc)[:120])
                    continue

        except Exception as exc:
            logger.debug("form_discovery_error  error=%r", str(exc))

        if not candidates:
            logger.debug("iframe_check_start")
            try:
                frames = page.frames
                logger.debug("frames_found  count=%d", len(frames))
                for frame_idx, frame in enumerate(frames):
                    if frame == page.main_frame:
                        continue
                    try:
                        logger.debug("iframe_check  index=%d  url=%r", frame_idx, frame.url[:100])
                        for selector in password_selectors:
                            try:
                                iframe_inputs = frame.locator(selector).all()
                                if iframe_inputs:
                                    logger.debug("iframe_password_found  index=%d  count=%d",
                                                 frame_idx, len(iframe_inputs))
                            except Exception:
                                pass
                    except Exception as exc:
                        logger.debug("iframe_error  index=%d  error=%r", frame_idx, str(exc))
            except Exception as exc:
                logger.debug("iframe_check_error  error=%r", str(exc))

        candidates.sort(key=lambda x: x.confidence, reverse=True)

        seen_forms: set = set()
        unique_candidates = []
        for candidate in candidates:
            fingerprint = (
                f"{candidate.root_selector}|{candidate.password_field}|"
                f"{candidate.username_fields[0] if candidate.username_fields else 'none'}"
            )
            if fingerprint not in seen_forms:
                seen_forms.add(fingerprint)
                unique_candidates.append(candidate)
            else:
                logger.debug("form_duplicate_dropped  fingerprint=%r", fingerprint[:80])

        if len(unique_candidates) < len(candidates):
            logger.debug("forms_deduplicated  before=%d  after=%d", len(candidates), len(unique_candidates))

        logger.debug("form_discovery_complete  forms=%d", len(unique_candidates))
        return unique_candidates

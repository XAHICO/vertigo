"""Username/password fill and submission strategies."""

import logging
from playwright.sync_api import Page
from .form_detector import CandidateForm

logger = logging.getLogger("vertigo.auth.orchestrator")


class Orchestrator:
    """Handle login form filling and submission."""

    def __init__(self, username: str, password: str, mute: bool = False):
        self.username = username
        self.password = password
        self.mute = mute

    def attempt_login(self, page: Page, form: CandidateForm) -> bool:
        logger.debug("login_attempt_start  confidence=%.2f", form.confidence)

        try:
            page.wait_for_timeout(500)

            username_filled = False
            for user_field in form.username_fields:
                try:
                    user_input = page.locator(user_field).first
                    if user_input.is_visible(timeout=2000):
                        user_input.click()
                        user_input.fill(self.username, timeout=5000)
                        user_input.dispatch_event("input")
                        user_input.dispatch_event("change")
                        username_filled = True
                        logger.debug("username_filled  selector=%r", user_field)
                        break
                except Exception as exc:
                    logger.debug("username_fill_error  selector=%r  error=%r", user_field, str(exc))
                    continue

            if not username_filled:
                logger.debug("login_failed  reason=username_field_not_fillable")
                return False

            pwd_input = None
            try:
                pwd_input = page.locator(form.password_field).first
                pwd_input.click()
                pwd_input.fill(self.password, timeout=5000)
                pwd_input.dispatch_event("input")
                pwd_input.dispatch_event("change")
                logger.debug("password_filled")
            except Exception as exc:
                logger.debug("login_failed  reason=password_fill_error  error=%r", str(exc))
                return False

            page.wait_for_timeout(1000)

            submit_success = False
            for trigger in form.submit_triggers:
                try:
                    submit_btn = page.locator(trigger).first
                    if not submit_btn.is_visible(timeout=2000):
                        continue
                    elem_info = submit_btn.evaluate(
                        "(el) => ({ tag: el.tagName, type: el.type, value: el.value, text: el.textContent?.trim() })"
                    )
                    if elem_info["type"] in ["text", "password", "email", "tel"]:
                        logger.debug("submit_skip  trigger=%r  reason=not_a_submit_element  type=%r",
                                     trigger, elem_info["type"])
                        continue
                    logger.debug("submit_click  trigger=%r  element=%r", trigger, elem_info)
                    try:
                        with page.expect_navigation(timeout=5000, wait_until="domcontentloaded"):
                            submit_btn.click(timeout=5000)
                        logger.debug("submit_navigation_occurred")
                    except Exception as nav_err:
                        logger.debug("submit_no_navigation  reason=%r", type(nav_err).__name__)
                        page.wait_for_timeout(1000)
                    submit_success = True
                    break
                except Exception as exc:
                    logger.debug("submit_click_error  trigger=%r  error=%r", trigger, str(exc)[:100])
                    continue

            if not submit_success:
                logger.debug("submit_fallback  method=enter_key")
                try:
                    with page.expect_navigation(timeout=5000, wait_until="domcontentloaded"):
                        pwd_input.press("Enter")
                except Exception:
                    page.wait_for_timeout(1000)

            page.wait_for_timeout(1000)
            return True

        except Exception as exc:
            logger.debug("login_attempt_error  error=%r", str(exc))
            return False

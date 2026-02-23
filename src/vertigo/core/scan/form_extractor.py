"""Form and input discovery."""

import logging
from typing import List, Dict, Any
from dataclasses import dataclass
from urllib.parse import urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger("vertigo.scan.form_extractor")


@dataclass
class DiscoveredForm:
    form_id: str
    url: str
    action: str
    method: str
    fields: List[Dict[str, Any]]
    classification: str
    requires_auth: bool


class FormExtractor:
    """Extract forms from HTML pages."""

    def __init__(self, mute: bool = False):
        self.mute = mute

    def extract_forms(self, soup: BeautifulSoup, url: str, requires_auth: bool = False) -> List[DiscoveredForm]:
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
                classification = self._classify_form(fields)
                forms.append(DiscoveredForm(
                    form_id=form_id,
                    url=url,
                    action=urljoin(url, action),
                    method=method,
                    fields=fields,
                    classification=classification,
                    requires_auth=requires_auth,
                ))
            except Exception as exc:
                logger.debug("form_extraction_error  url=%r  error=%r", url, str(exc))
                continue
        return forms

    def _classify_form(self, fields: List[Dict]) -> str:
        field_names = [f["name"].lower() for f in fields]
        if any("password" in n or "pass" in n for n in field_names):
            return "login" if any("user" in n or "email" in n for n in field_names) else "password_change"
        if any("search" in n or "query" in n or n == "q" for n in field_names):
            return "search"
        if any("email" in n or "message" in n or "contact" in n for n in field_names):
            return "contact"
        if len(fields) > 5 and any("email" in n for n in field_names):
            return "registration"
        return "generic"

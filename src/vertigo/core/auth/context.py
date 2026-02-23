"""Auth session dataclass"""

from typing import Optional, Dict, List, Any
from dataclasses import dataclass


@dataclass
class AuthSessionContext:
    """Captured authenticated session"""
    cookies: List[Dict]
    headers: Dict[str, str]
    storage: Dict[str, Any]
    fingerprint: str
    expires: Optional[int]
    success: bool
    failure_reason: Optional[str]
    target: str


"""Endpoint vs static resource classification"""

import os
import re
from typing import List
from urllib.parse import urlparse, parse_qs


# Static file extensions to track separately
STATIC_EXTENSIONS = {'.js', '.css', '.map', '.wasm'}


def normalize_path(path: str) -> str:
    """Normalize path by replacing numeric IDs with placeholders and
    stripping trailing slashes so that /dvwa and /dvwa/ are treated as
    the same endpoint.
    
    Ensures empty or None paths become '/' to prevent duplicate endpoints.
    """
    # Handle empty/None paths
    if not path or path == '':
        return '/'
    
    # Replace numeric IDs with placeholders
    normalized = re.sub(r'/\d+(?=/|$)', '/{id}', path)
    
    # Strip trailing slash (but keep bare '/')
    if len(normalized) > 1 and normalized.endswith('/'):
        normalized = normalized.rstrip('/')
    
    return normalized


def extract_params(url: str) -> List[str]:
    """Extract parameter names from URL"""
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query)
        return list(params.keys())
    return []


def canonical_endpoint(method: str, url: str, params: List[str]) -> str:
    """Create canonical endpoint identifier"""
    parsed = urlparse(url)
    path = normalize_path(parsed.path)
    sorted_params = sorted(params)
    method = method.upper()
    
    if sorted_params:
        param_str = ','.join(sorted_params)
        return f"{method} {path} params={param_str}"
    return f"{method} {path}"


def is_static_resource(url: str) -> bool:
    """Check if URL points to a static resource"""
    parsed = urlparse(url)
    path = parsed.path or '/'
    extension = os.path.splitext(path)[1].lower()
    return extension in STATIC_EXTENSIONS

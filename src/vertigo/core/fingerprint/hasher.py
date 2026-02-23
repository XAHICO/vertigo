"""SHA-256 hashing utilities for fingerprinting"""

import hashlib
from typing import Dict, Set


def hash_string(s: str) -> str:
    """Generate SHA-256 hash of string"""
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def strip_default_port(scheme: str, netloc: str) -> str:
    """Strip default port from netloc (80 for http, 443 for https).
    
    Katana, browsers, and other tools normalise URLs by removing the
    default port, so ``localhost:80`` becomes ``localhost``.  If the
    target was given *with* an explicit default port we must strip it
    so that downstream netloc comparisons don't false-negative.
    """
    netloc = netloc.lower()
    if scheme == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    elif scheme == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]
    return netloc


def compute_asset_fingerprint(endpoints: Set[str], 
                              static_resources: Dict[str, Dict],
                              headers: Dict[str, str],
                              cookies: Dict[str, Dict]) -> str:
    """Compute composite asset fingerprint from all discovered resources"""
    all_hashes = []
    
    # Hash endpoints
    for endpoint in sorted(endpoints):
        all_hashes.append(hash_string(endpoint))
    
    # Hash static resources
    for path in sorted(static_resources.keys()):
        all_hashes.append(static_resources[path]['content_hash'])
    
    # Hash headers
    for header_name in sorted(headers.keys()):
        all_hashes.append(headers[header_name])
    
    # Hash cookies
    for cookie_name in sorted(cookies.keys()):
        all_hashes.append(cookies[cookie_name]['attributes_hash'])
    
    # Combine all hashes
    combined = '|'.join(all_hashes) if all_hashes else ''
    return hash_string(combined)

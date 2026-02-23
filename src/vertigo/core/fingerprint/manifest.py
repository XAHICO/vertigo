"""Fingerprint manifest builder"""

from typing import Dict, Set
from .hasher import hash_string


def build_manifest(target: str, entry: str, scan_begin: int, scan_end: int,
                  status: str, partial: bool, urls_crawled: int,
                  endpoints: Set[str], static_resources: Dict[str, Dict],
                  headers: Dict[str, str], cookies: Dict[str, Dict],
                  asset_hash: str) -> Dict:
    """Build fingerprint manifest from crawl results"""
    manifest = {
        'metadata': {
            'target': target,
            'entry': entry,
            'scan_begin': scan_begin,
            'scan_end': scan_end,
            'status': status,
            'partial': partial,
            'stats': {
                'urls_crawled': urls_crawled,
                'endpoints_found': len(endpoints),
                'static_resources_found': len(static_resources),
                'headers_tracked': len(headers),
                'cookies_found': len(cookies),
            }
        },
        'asset_fingerprint': asset_hash,
        'resource_hashes': {
            'endpoints': {
                endpoint: hash_string(endpoint)
                for endpoint in sorted(endpoints)
            },
            'static_resources': {
                path: resource['content_hash']
                for path, resource in sorted(static_resources.items())
            },
            'headers': headers,
            'cookies': {
                name: cookie['attributes_hash']
                for name, cookie in sorted(cookies.items())
            }
        }
    }
    
    return manifest

"""BFS crawl and depth control."""

import logging
from collections import deque
from typing import Set, Deque, Tuple

logger = logging.getLogger("vertigo.scan.navigator")


class Navigator:
    """BFS queue management and depth control."""

    def __init__(self, max_depth: int = 10, max_urls: int = 5000, mute: bool = False):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.mute = mute
        self.queue: Deque[Tuple[str, int]] = deque()
        self.visited: Set[str] = set()

    def add_url(self, url: str, depth: int = 0):
        if url not in self.visited:
            self.queue.append((url, depth))

    def add_links(self, links: list, current_depth: int):
        if current_depth < self.max_depth:
            for link in links:
                if link not in self.visited:
                    self.queue.append((link, current_depth + 1))

    def get_next(self) -> Tuple[str, int] | None:
        if self.queue and len(self.visited) < self.max_urls:
            return self.queue.popleft()
        return None

    def mark_visited(self, url: str):
        self.visited.add(url)

    def is_visited(self, url: str) -> bool:
        return url in self.visited

    def should_continue(self) -> bool:
        return bool(self.queue) and len(self.visited) < self.max_urls

    def get_stats(self) -> dict:
        return {
            "urls_in_queue": len(self.queue),
            "urls_visited": len(self.visited),
            "max_urls": self.max_urls,
            "max_depth": self.max_depth,
        }

"""Rate limiting and safety controls for the crawler"""

import time
from typing import Tuple, List


class SafetyThrottle:
    """Rate limiting and safety controls to prevent accidental disruption"""
    
    def __init__(self, max_rpm: int = 60, max_errors: int = 10, 
                 allowed_methods: Tuple[str, ...] = ('GET',)):
        self.max_rpm = max_rpm
        self.max_errors = max_errors
        self.allowed_methods = allowed_methods
        self.request_times: List[float] = []
        self.error_count = 0
        self.paused = False
    
    def can_make_request(self, method: str) -> Tuple[bool, str]:
        """Check if request is safe and allowed"""
        
        # Paused due to errors
        if self.paused:
            return False, "Crawler paused due to error threshold"
        
        # Method check
        if method.upper() not in self.allowed_methods:
            return False, f"Method {method} not allowed (GET-only mode)"
        
        # Rate limit check
        now = time.time()
        self.request_times.append(now)
        
        # Count requests in last minute
        minute_ago = now - 60
        recent = sum(1 for t in self.request_times if t > minute_ago)
        
        if recent >= self.max_rpm:
            return False, "Rate limit exceeded"
        
        return True, ""
    
    def record_error(self):
        """Record error, potentially pause crawler"""
        self.error_count += 1
        if self.error_count >= self.max_errors:
            self.paused = True
    
    def record_success(self):
        """Record successful request"""
        # Decay error count on success
        if self.error_count > 0:
            self.error_count -= 1

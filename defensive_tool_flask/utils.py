import re
import json
import os
import time
from collections import defaultdict, deque

LOG_IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

class Blocklist:
    def __init__(self, path):
        self.path = path
        self._data = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}
        else:
            self._data = {}

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    def add(self, ip, reason="manual"):
        self._data[ip] = {"reason": reason, "timestamp": time.time()}
        self._save()

    def remove(self, ip):
        if ip in self._data:
            del self._data[ip]
            self._save()

    def is_blocked(self, ip):
        return ip in self._data

    def list(self):
        return self._data

class LogScanner:
    """
    Simple log scanner that finds repeated failed login lines and flags IPs that exceed threshold.
    It returns a dict of ip -> count and example lines.
    """
    def __init__(self, threshold=5):
        self.threshold = threshold
        self.fail_patterns = [
            re.compile(r"failed login", re.IGNORECASE),
            re.compile(r"authentication failure", re.IGNORECASE),
            re.compile(r"invalid user", re.IGNORECASE),
            re.compile(r"failed password", re.IGNORECASE),
        ]

    def scan_text(self, text):
        ip_counts = defaultdict(int)
        ip_examples = defaultdict(list)
        for i, line in enumerate(text.splitlines()):
            if any(p.search(line) for p in self.fail_patterns):
                m = LOG_IP_PATTERN.search(line)
                if m:
                    ip = m.group(1)
                    ip_counts[ip] += 1
                    if len(ip_examples[ip]) < 3:
                        ip_examples[ip].append(line.strip())
        suspicious = {}
        for ip, cnt in ip_counts.items():
            if cnt >= self.threshold:
                suspicious[ip] = {"count": cnt, "examples": ip_examples[ip]}
        return suspicious

class RateLimiter:
    """
    Very small in-memory rate limiter per IP using a deque of timestamps.
    Not suitable for distributed deployments, but fine for a demo defensive tool.
    """
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.data = {}  # ip -> deque of timestamps

    def allow_request(self, ip):
        now = time.time()
        dq = self.data.get(ip)
        if dq is None:
            dq = deque()
            self.data[ip] = dq
        # pop outdated
        while dq and dq[0] <= now - self.window:
            dq.popleft()
        if len(dq) >= self.max_requests:
            return False, 0
        dq.append(now)
        return True, self.max_requests - len(dq)

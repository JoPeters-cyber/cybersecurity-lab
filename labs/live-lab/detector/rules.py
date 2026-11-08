"""Detection rules for the lab.

Two kinds of rules:
  * SignatureRule  - fires on a single request matching a regex (request line,
                     user-agent, status, ...). Good for payload signatures.
  * RateRule       - fires when a pattern repeats > threshold times from one
                     source IP inside a sliding time window. Good for brute
                     force / scanning where a single request looks benign.

Each firing produces an alert dict the detector formats and prints. Edit this
file to tune thresholds or add your own rules, then restart the detector:
    docker compose restart detector
"""
import re
from collections import defaultdict, deque


class SignatureRule:
    def __init__(self, sid, name, severity, field, pattern, mitre=""):
        self.sid = sid
        self.name = name
        self.severity = severity
        self.field = field            # one of: request, user_agent, status
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.mitre = mitre

    def check(self, event):
        value = event.get(self.field, "") or ""
        if self.pattern.search(value):
            return {
                "sid": self.sid,
                "name": self.name,
                "severity": self.severity,
                "mitre": self.mitre,
                "src_ip": event["src_ip"],
                "detail": f'{self.field}="{value}"',
            }
        return None


class RateRule:
    def __init__(self, sid, name, severity, field, pattern,
                 threshold, window_secs, mitre=""):
        self.sid = sid
        self.name = name
        self.severity = severity
        self.field = field
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.threshold = threshold
        self.window = window_secs
        self.mitre = mitre
        self._hits = defaultdict(deque)   # src_ip -> deque[timestamps]
        self._muted_until = defaultdict(float)

    def check(self, event):
        value = event.get(self.field, "") or ""
        if not self.pattern.search(value):
            return None
        ip = event["src_ip"]
        now = event["epoch"]
        dq = self._hits[ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        # avoid alert spam: one alert per window once tripped
        if len(dq) >= self.threshold and now >= self._muted_until[ip]:
            self._muted_until[ip] = now + self.window
            return {
                "sid": self.sid,
                "name": self.name,
                "severity": self.severity,
                "mitre": self.mitre,
                "src_ip": ip,
                "detail": f"{len(dq)} matching requests in {self.window}s",
            }
        return None


# --- Rule set -------------------------------------------------------------
RULES = [
    SignatureRule(
        1001, "SQL injection attempt", "high", "request",
        r"(\bunion\b(\s|\+|%20)+\bselect\b|\bor\b(\s|\+|%20)+\d+\s*=\s*\d+|(%27|')(\s|\+|%20)*or(\s|\+|%20)|(%27|')\s*=\s*(%27|')|information_schema|sleep\s*\(|benchmark\s*\()",
        mitre="T1190 Exploit Public-Facing Application",
    ),
    SignatureRule(
        1002, "OS command injection attempt", "high", "request",
        r"(;|%3b|\|\||&&|%26%26|`|\$\()\s*(cat|ls|id|whoami|uname|ping|nc|bash|sh)\b",
        mitre="T1059 Command and Scripting Interpreter",
    ),
    SignatureRule(
        1003, "Path traversal / local file inclusion", "high", "request",
        r"(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|c:\\windows)",
        mitre="T1083 File and Directory Discovery",
    ),
    SignatureRule(
        1004, "Reflected XSS payload", "medium", "request",
        r"(<script|%3cscript|onerror\s*=|onload\s*=|javascript:)",
        mitre="T1059.007 JavaScript",
    ),
    SignatureRule(
        1005, "Known scanner / tool user-agent", "medium", "user_agent",
        r"(sqlmap|nikto|nmap|hydra|curl|wfuzz|dirbuster|gobuster|masscan)",
        mitre="T1595 Active Scanning",
    ),
    RateRule(
        2001, "Login brute-force", "high", "request",
        r"POST\s+/login\.php", threshold=10, window_secs=30,
        mitre="T1110 Brute Force",
    ),
    RateRule(
        2002, "Web content scanning / high 404 rate", "medium", "status",
        r"^404$", threshold=15, window_secs=20,
        mitre="T1595.003 Wordlist Scanning",
    ),
]

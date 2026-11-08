"""Lab detector: tails the nginx access log and applies rules.py.

This is a deliberately small stand-in for a real SIEM (Wazuh/Elastic). It
shows the same core loop: collect -> parse -> evaluate rules -> alert.
Alerts print to stdout (``docker compose logs -f detector``) and append to
/logs/alerts.log.
"""
import os
import re
import time
from datetime import datetime

from rules import RULES

ACCESS_LOG = os.environ.get("ACCESS_LOG", "/logs/access.log")
ALERT_LOG = os.environ.get("ALERT_LOG", "/logs/alerts.log")

# combined log format:
# 172.18.0.1 - - [07/Nov/2026:07:30:00 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8.0"
LINE_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def parse(line):
    m = LINE_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["epoch"] = time.time()  # wall-clock arrival; fine for a local lab
    return d


def alert(a):
    icon = SEV_ICON.get(a["severity"], "")
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (f"{icon} [{a['severity'].upper()}] sid:{a['sid']} {a['name']} "
           f"from {a['src_ip']} | {a['detail']}"
           + (f" | MITRE {a['mitre']}" if a.get("mitre") else ""))
    print(f"{stamp}  {msg}", flush=True)
    try:
        with open(ALERT_LOG, "a") as fh:
            fh.write(f"{stamp}  {msg}\n")
    except OSError:
        pass  # /logs mounted read-only is fine; stdout still works


def follow(path):
    """Yield new lines appended to path, waiting for the file to appear."""
    while not os.path.exists(path):
        print(f"waiting for {path} ...", flush=True)
        time.sleep(1)
    with open(path, "r") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line.rstrip("\n")


def main():
    print(f"detector online. rules loaded: {len(RULES)}. tailing {ACCESS_LOG}",
          flush=True)
    for line in follow(ACCESS_LOG):
        event = parse(line)
        if not event:
            continue
        for rule in RULES:
            hit = rule.check(event)
            if hit:
                alert(hit)


if __name__ == "__main__":
    main()

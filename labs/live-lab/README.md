# 🧪 Attack / Defend Practice Lab

A self-contained, Docker-based cybersecurity lab you can run on one machine. You
attack a deliberately vulnerable web app and watch a tiny SIEM-style detector
catch you in real time — then tune the detections yourself.

> ⚠️ **Lab use only.** The target is *intentionally* vulnerable. Never expose it
> to the internet or run these attacks against systems you do not own.

## 🏗️ What's inside

| Service    | Role                                                                 |
|------------|----------------------------------------------------------------------|
| `dvwa`     | [DVWA](https://github.com/digininja/DVWA) — the vulnerable target.   |
| `proxy`    | nginx reverse proxy. Writes one clean `combined` access log to a shared volume — your single SIEM collection point. |
| `attacker` | Debian box preloaded with `nmap`, `hydra`, `sqlmap`, `curl` + small wordlists. |
| `detector` | Python log-watcher that tails the proxy log and applies rules in [`detector/rules.py`](detector/rules.py). |

```text
attacker ──HTTP──▶ proxy (nginx) ──▶ dvwa
                     │
                     └─ /logs/access.log ──▶ detector ──▶ 🔴 alerts
```

## 🚀 Quick start

```bash
docker compose up -d --build        # build & start all 4 containers
```

1. Open the target: <http://localhost:8080> — log in with **admin / password**,
   then click **Create / Reset Database**.
2. Set **DVWA Security** to **Low** (DVWA Security tab) for the first run.
3. In one terminal, watch detections live:

   ```bash
   docker compose logs -f detector
   ```

4. In another terminal, get a shell on the attacker box:

   ```bash
   docker compose exec attacker bash
   ```

Now work through the exercises in [`exercises/`](exercises/). Each one has you
run an attack, confirm the detector caught it, then tune a rule.

When you're done:

```bash
docker compose down -v              # stop and remove everything (incl. logs)
```

## 🎯 Exercises

| # | Exercise | Technique | MITRE ATT&CK |
|---|----------|-----------|--------------|
| 1 | [SQL injection](exercises/01-sql-injection.md)        | Auth bypass / data exfil | T1190 |
| 2 | [Login brute force](exercises/02-brute-force.md)      | Credential attack        | T1110 |
| 3 | [Command injection](exercises/03-command-injection.md)| RCE                      | T1059 |
| 4 | [Recon & scanning](exercises/04-recon-scanning.md)    | Active scanning          | T1595 |

## 🔍 How detection works

The detector is a deliberately small stand-in for a real SIEM (Wazuh, Elastic).
It runs the same core loop — **collect → parse → evaluate rules → alert** — so
the rule-writing skills transfer. Two rule types live in
[`detector/rules.py`](detector/rules.py):

- **`SignatureRule`** — fires on a single request matching a regex (payload in
  the request line, a scanner user-agent, a status code).
- **`RateRule`** — fires when a pattern repeats past a threshold from one source
  IP inside a sliding time window (brute force, scanning).

Alerts print to `docker compose logs -f detector` and append to
`/logs/alerts.log` inside the `detector` container. Edit the rules, then:

```bash
docker compose restart detector
```

## 🧯 Troubleshooting

- **Port 8080 in use** — change the `proxy` port mapping in `docker-compose.yml`
  (e.g. `"8081:80"`).
- **DVWA "database not set up"** — log in and click *Create / Reset Database*.
- **No alerts** — confirm traffic reaches the proxy: `docker compose logs proxy`,
  and that the detector is tailing: `docker compose logs detector`.

## 📚 Next steps

- Lower DVWA security to **Medium/High** and see which detections still fire.
- Add your own `SignatureRule`/`RateRule` and map it to an ATT&CK technique.
- Point a real Wazuh/Elastic agent at `/logs/access.log` to graduate from the
  toy detector to a full SIEM.

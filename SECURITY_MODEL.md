# Security model

This repository is a public, documentation-only portfolio of an isolated VirtualBox lab (host-only network, Metasploitable 2, Nmap, Wireshark): a single `README.md`. It has no application code, CI, or deployable service.

## Components

| Name | Covers |
|---|---|
| Lab Portfolio Docs | `README.md` |

## Trust boundaries and entry points

- Public GitHub: anyone can read the docs.

## Attackers

There is no targeted adversary; these are portfolio and learning docs. The relevant actors are opportunistic: someone harvesting leaked tokens or credentials from public repositories, or a tampered upstream or third-party file reaching readers.

## Assets (in priority order)

1. The owner's GitHub account and repository integrity: no tokens or credentials that grant write access, and no tampered content.
2. Reader safety: no PDFs with active content (JavaScript, launch actions, embedded files) and no copy-paste commands that are dangerous beyond their stated lab purpose.
3. Personal and lab details (emails, internal IPs, domain names). These are low value because the labs are isolated.

## Out of scope / accepted risk

- Intentional offensive-security teaching content, such as attack commands, tool lists, and payload or SQL-injection examples, is educational by design and accepted.
- Lab-only identifiers (RFC1918 example IPs, lab domain names, example account names) are low risk because the labs are isolated and not internet-reachable.

## Existing controls

- Labs run on isolated private or host-only networks, with VM snapshots taken before risky experiments.
- Only the owner's GitHub account has write access.

# INC-20261014-001: Account compromise via SSH brute force (203.0.113.45)

| | |
|---|---|
| **Severity** | Critical (risk 100/100) |
| **Status** | Containment staged automatically, awaiting analyst review |
| **Created** | 2026-10-14 12:10:01 |
| **Indicator** | `203.0.113.45` (ip) |
| **Detections** | SSH Brute Force, Successful Login After Brute Force |
| **MITRE ATT&CK** | T1078, T1110, T1110.001 |

## Enrichment

- Internal address: no
- Allowlisted: no
- Reputation score: 95/100 (ssh-bruteforce, botnet)
- Intel sources: local feed
- Note: RFC 5737 documentation range, used as a stand-in attacker in this lab

## Evidence

**SSH Brute Force** (1 result)

- src_ip=203.0.113.45; failures=45; users_tried=1; usernames=admin

**Successful Login After Brute Force** (1 result)

- src_ip=203.0.113.45; failures=45; successes=1; compromised_user=admin

## Automated actions

- **block_ip** 203.0.113.45: added to blocklist and pf rules
- **lock_account** admin: lock command staged for approval
- **notify** SOC channel: console only (set SOC_WEBHOOK_URL to send to Slack or Teams)

## Analyst next steps

1. Confirm no successful login followed from this IP.
2. Check whether the targeted usernames exist and whether any are privileged.
3. Treat the account as compromised: reset its password and revoke SSH keys.
4. Review everything the account did after the successful login (sudo, downloads, new users, cron).
5. Isolate the host if any post-compromise activity is found.

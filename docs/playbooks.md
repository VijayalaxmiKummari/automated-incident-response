# Playbooks

Each Splunk detection maps to a playbook in [`air/playbooks.py`](../air/playbooks.py). A playbook defines the indicator to extract, the base risk score, the MITRE techniques, the automated actions and the steps left for an analyst.

Alerts that share an indicator are merged into one incident before any playbook runs. The incident takes the highest base score, all the MITRE techniques, and every action and step from the playbooks involved.

---

## Successful Login After Brute Force

| | |
|---|---|
| Indicator | `src_ip`, plus `compromised_user` |
| Base risk | 90 |
| MITRE | T1110 Brute Force, T1078 Valid Accounts |
| Automated | Block the IP, stage a lock on the compromised account, notify the SOC |

**Analyst steps**
1. Treat the account as compromised: reset its password and revoke SSH keys.
2. Review everything the account did after the successful login (sudo, downloads, new users, cron).
3. Isolate the host if any post-compromise activity is found.

## Suspicious Sudo Command

| | |
|---|---|
| Indicator | `sudo_user` |
| Base risk | 70 |
| MITRE | T1548.003, T1003.008, T1105 |
| Automated | Stage a lock on the account |

**Analyst steps**
1. Confirm with the account owner whether the commands were expected.
2. If `/etc/shadow` was read, reset every local password.
3. Collect any downloaded file (e.g. in `/tmp`) for analysis before removing it.

## SQL Injection Attempt

| | |
|---|---|
| Indicator | `clientip` |
| Base risk | 60 |
| MITRE | T1190 Exploit Public-Facing Application |
| Automated | Block the IP |

**Analyst steps**
1. Requests that returned HTTP 500 suggest the parameter is injectable: raise with the web team.
2. Review database logs for queries matching the payloads.

## SSH Brute Force

| | |
|---|---|
| Indicator | `src_ip` |
| Base risk | 50 |
| MITRE | T1110.001 Password Guessing |
| Automated | Block the IP |

**Analyst steps**
1. Confirm no successful login followed from this IP.
2. Check whether the targeted usernames exist and whether any are privileged.

## Password Spraying

| | |
|---|---|
| Indicator | `src_ip` |
| Base risk | 50 |
| MITRE | T1110.003 Password Spraying |
| Automated | Block the IP |

**Analyst steps**
1. Check if any sprayed username exists locally and has a weak password.
2. Consider account lockout or fail2ban for repeated failures.

## Web Directory Scanning

| | |
|---|---|
| Indicator | `clientip` |
| Base risk | 30 |
| MITRE | T1595.003 Wordlist Scanning |
| Automated | Block the IP only if threat intel or correlation lifts the risk to 60 or more |

**Analyst steps**
1. Check whether any probed path returned 200 (e.g. `/.env`, `/.git/config`).

---

## Decision rules for blocking

An IP is blocked only when **all** of these are true:

1. It is not in an internal network listed in `config.json`
2. It is not on the allowlist
3. The incident's risk score is at or above `block_threshold` (default 60)

Otherwise the block is recorded as skipped, with the reason, and the incident goes to an analyst.

# INC-20261014-004: SQL injection attempts (203.0.113.99)

| | |
|---|---|
| **Severity** | High (risk 81/100) |
| **Status** | Containment staged automatically, awaiting analyst review |
| **Created** | 2026-10-14 12:10:01 |
| **Indicator** | `203.0.113.99` (ip) |
| **Detections** | Web Directory Scanning, SQL Injection Attempt |
| **MITRE ATT&CK** | T1190, T1595.003 |

## Enrichment

- Internal address: no
- Allowlisted: no
- Reputation score: 80/100 (web-scanner, sqlmap)
- Intel sources: local feed
- Note: RFC 5737 documentation range, used as a stand-in attacker in this lab

## Evidence

**Web Directory Scanning** (1 result)

- clientip=203.0.113.99; errors=54; unique_paths=18; user_agents=gobuster/3.6

**SQL Injection Attempt** (5 results)

- _time=2026-10-14T10:46:51.000+01:00; clientip=203.0.113.99; status=500; useragent=sqlmap/1.8; decoded=/products?id=1' OR '1'='1
- _time=2026-10-14T10:46:59.000+01:00; clientip=203.0.113.99; status=500; useragent=sqlmap/1.8; decoded=/products?id=1 UNION SELECT username,password FROM users--
- _time=2026-10-14T10:47:06.000+01:00; clientip=203.0.113.99; status=500; useragent=sqlmap/1.8; decoded=/products?q='; DROP TABLE users--
- _time=2026-10-14T10:47:14.000+01:00; clientip=203.0.113.99; status=200; useragent=sqlmap/1.8; decoded=/products?id=1 AND SLEEP(5)
- _time=2026-10-14T10:47:22.000+01:00; clientip=203.0.113.99; status=500; useragent=sqlmap/1.8; decoded=/products?user=admin'--

## Automated actions

- **block_ip** 203.0.113.99: added to blocklist and pf rules

## Analyst next steps

1. Check whether any probed path returned 200 (e.g. /.env, /.git/config).
2. Requests that returned HTTP 500 suggest the parameter is injectable: raise with the web team.
3. Review database logs for queries matching the payloads.

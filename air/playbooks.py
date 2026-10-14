"""Playbooks: what each detection means, how risky it is, and what to do about it.

Alerts are grouped by indicator (an attacker IP or a local user account), so several
detections against the same IP become one incident instead of several tickets.
"""

PLAYBOOKS = {
    "SSH Brute Force": {
        "base_risk": 50,
        "mitre": ["T1110.001"],
        "title": "SSH brute force",
        "ip_field": "src_ip",
        "actions": ["block_ip"],
        "steps": [
            "Confirm no successful login followed from this IP.",
            "Check whether the targeted usernames exist and whether any are privileged.",
        ],
    },
    "Successful Login After Brute Force": {
        "base_risk": 90,
        "mitre": ["T1110", "T1078"],
        "title": "Account compromise via SSH brute force",
        "ip_field": "src_ip",
        "user_field": "compromised_user",
        "actions": ["block_ip", "lock_account"],
        "steps": [
            "Treat the account as compromised: reset its password and revoke SSH keys.",
            "Review everything the account did after the successful login (sudo, downloads, new users, cron).",
            "Isolate the host if any post-compromise activity is found.",
        ],
    },
    "Password Spraying": {
        "base_risk": 50,
        "mitre": ["T1110.003"],
        "title": "Password spraying",
        "ip_field": "src_ip",
        "actions": ["block_ip"],
        "steps": [
            "Check if any sprayed username exists locally and has a weak password.",
            "Consider account lockout or fail2ban for repeated failures.",
        ],
    },
    "Suspicious Sudo Command": {
        "base_risk": 70,
        "mitre": ["T1548.003", "T1003.008", "T1105"],
        "title": "Suspicious privileged command",
        "user_field": "sudo_user",
        "actions": ["lock_account"],
        "steps": [
            "Confirm with the account owner whether the commands were expected.",
            "If /etc/shadow was read, reset every local password.",
            "Collect any downloaded file (e.g. in /tmp) for analysis before removing it.",
        ],
    },
    "Web Directory Scanning": {
        "base_risk": 30,
        "mitre": ["T1595.003"],
        "title": "Web directory scanning",
        "ip_field": "clientip",
        "actions": ["block_ip"],
        "steps": [
            "Check whether any probed path returned 200 (e.g. /.env, /.git/config).",
        ],
    },
    "SQL Injection Attempt": {
        "base_risk": 60,
        "mitre": ["T1190"],
        "title": "SQL injection attempts",
        "ip_field": "clientip",
        "actions": ["block_ip"],
        "steps": [
            "Requests that returned HTTP 500 suggest the parameter is injectable: raise with the web team.",
            "Review database logs for queries matching the payloads.",
        ],
    },
}

INTEL_WEIGHT = 0.2       # how much threat-intel reputation (0-100) adds to risk
CORRELATION_BONUS = 5    # extra risk per additional distinct detection on the same indicator


def severity_for(risk):
    if risk >= 85:
        return "Critical"
    if risk >= 60:
        return "High"
    if risk >= 40:
        return "Medium"
    return "Low"


def _first(value):
    """Splunk returns multivalue fields as lists."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def group_alerts(alerts):
    """Turn raw detection rows into incidents keyed by indicator."""
    incidents = {}
    for alert in alerts:
        name, row = alert["detection"], alert["result"]
        pb = PLAYBOOKS.get(name)
        if not pb:
            continue
        if "ip_field" in pb and _first(row.get(pb["ip_field"])):
            key = ("ip", _first(row[pb["ip_field"]]))
        elif "user_field" in pb and _first(row.get(pb["user_field"])):
            key = ("user", _first(row[pb["user_field"]]))
        else:
            continue
        inc = incidents.setdefault(key, {"indicator_type": key[0], "indicator": key[1],
                                         "detections": {}, "users_to_lock": set()})
        inc["detections"].setdefault(name, []).append(row)
        if "lock_account" in pb["actions"]:
            user = _first(row.get(pb.get("user_field", ""))) or (key[1] if key[0] == "user" else None)
            if user:
                inc["users_to_lock"].add(user)
    return list(incidents.values())


def assess(incident, enrichment, block_threshold):
    """Score the incident and decide which actions are safe to take."""
    names = list(incident["detections"])
    base = max(PLAYBOOKS[n]["base_risk"] for n in names)
    reputation = enrichment.get("reputation", 0) if enrichment else 0
    risk = base + reputation * INTEL_WEIGHT + CORRELATION_BONUS * (len(names) - 1)
    risk = int(min(100, round(risk)))

    top = max(names, key=lambda n: PLAYBOOKS[n]["base_risk"])
    mitre = sorted({t for n in names for t in PLAYBOOKS[n]["mitre"]})
    steps = [s for n in names for s in PLAYBOOKS[n]["steps"]]

    decisions = []
    wanted = {a for n in names for a in PLAYBOOKS[n]["actions"]}

    if "block_ip" in wanted and incident["indicator_type"] == "ip":
        if enrichment.get("internal") or enrichment.get("allowlisted"):
            decisions.append(("skip_block", incident["indicator"],
                              "internal or allowlisted address, escalated to analyst instead"))
        elif risk < block_threshold:
            decisions.append(("skip_block", incident["indicator"],
                              f"risk {risk} below block threshold {block_threshold}"))
        else:
            decisions.append(("block_ip", incident["indicator"], "external attacker above risk threshold"))

    for user in sorted(incident["users_to_lock"]):
        decisions.append(("lock_account", user, "account used in confirmed malicious activity"))

    decisions.append(("create_ticket", None, ""))
    if risk >= 85:
        decisions.append(("notify", None, "critical incident"))

    return {
        "risk": risk,
        "severity": severity_for(risk),
        "title": PLAYBOOKS[top]["title"],
        "mitre": mitre,
        "steps": steps,
        "decisions": decisions,
    }

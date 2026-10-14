"""Automated Incident Response engine.

Pulls detection results from Splunk (or a sample file in --demo mode), groups them
into incidents, enriches the indicators, scores risk, and runs the playbook actions.
"""

import argparse
import getpass
import json
import os
import shutil
import sys
import time
from datetime import datetime

from .actions import ActionRunner
from .enrichment import Enricher
from .playbooks import PLAYBOOKS, assess, group_alerts
from .splunk_client import SplunkClient, SplunkError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
STATE = os.path.join(OUT, "state.json")

COLOURS = {"Critical": "\033[1;31m", "High": "\033[31m", "Medium": "\033[33m", "Low": "\033[36m"}
RESET = "\033[0m"


def load_config():
    with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as f:
        return json.load(f)


def load_state():
    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    return {"handled": [], "counter": {}}


def save_state(state):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def next_incident_id(state):
    day = datetime.now().strftime("%Y%m%d")
    n = state["counter"].get(day, 0) + 1
    state["counter"][day] = n
    return f"INC-{day}-{n:03d}"


def fetch_from_splunk(cfg):
    s = cfg["splunk"]
    user = os.environ.get("SPLUNK_USERNAME", s.get("username", "admin"))
    password = os.environ.get("SPLUNK_PASSWORD") or getpass.getpass(f"Splunk password for {user}: ")
    client = SplunkClient(s["host"], s["port"], user, password, app=s["app"], verify_tls=s["verify_tls"])
    alerts = []
    for name in PLAYBOOKS:
        saved_name = f"{cfg['saved_search_prefix']}{name}"
        spl = client.saved_search_spl(saved_name)
        rows = client.run(spl, earliest=s["earliest"])
        print(f"  {name:<38} {len(rows)} result(s)")
        alerts += [{"detection": name, "result": r} for r in rows]
    return alerts


def fetch_demo():
    with open(os.path.join(ROOT, "data", "sample_alerts.json"), encoding="utf-8") as f:
        alerts = json.load(f)
    counts = {}
    for a in alerts:
        counts[a["detection"]] = counts.get(a["detection"], 0) + 1
    for name in PLAYBOOKS:
        print(f"  {name:<38} {counts.get(name, 0)} result(s)")
    return alerts


def process(alerts, cfg, state):
    enricher = Enricher(os.path.join(ROOT, cfg["threat_intel_file"]),
                        cfg["internal_networks"], cfg["allowlist"])
    runner = ActionRunner(OUT)
    handled = set(state["handled"])
    summary = []

    for incident in group_alerts(alerts):
        keys = {f"{incident['indicator']}|{d}" for d in incident["detections"]}
        if keys <= handled:
            continue  # nothing new for this indicator since the last run

        enrichment = enricher.enrich_ip(incident["indicator"]) if incident["indicator_type"] == "ip" else {}
        a = assess(incident, enrichment, cfg["block_threshold"])
        inc_id = next_incident_id(state)
        detections = list(incident["detections"])
        taken = []

        for action, target, reason in a["decisions"]:
            if action == "block_ip":
                result = runner.block_ip(target, inc_id)
            elif action == "skip_block":
                action, result = "block_ip", f"skipped: {reason}"
            elif action == "lock_account":
                result = runner.lock_account(target, inc_id)
            else:
                continue
            taken.append((action, target, result))
            runner.audit(inc_id, action, target, result, a["severity"], detections)

        if any(d[0] == "notify" for d in a["decisions"]):
            result = runner.notify(inc_id, a, incident["indicator"])
            taken.append(("notify", "SOC channel", result))
            runner.audit(inc_id, "notify", "SOC channel", result, a["severity"], detections)

        path = runner.create_ticket(inc_id, incident, enrichment, a, taken)
        runner.audit(inc_id, "create_ticket", os.path.relpath(path, ROOT), "created", a["severity"], detections)

        handled |= keys
        summary.append((inc_id, a, incident, taken))

    state["handled"] = sorted(handled)
    return summary


def print_summary(summary):
    if not summary:
        print("\nNo new incidents. Everything already handled.")
        return
    print(f"\n{len(summary)} incident(s) created:\n")
    for inc_id, a, incident, taken in sorted(summary, key=lambda s: -s[1]["risk"]):
        c = COLOURS.get(a["severity"], "")
        print(f"{c}[{a['severity'].upper():<8}]{RESET} {inc_id}  {a['title']} ({incident['indicator']})"
              f"  risk {a['risk']}/100")
        print(f"             detections: {', '.join(incident['detections'])}")
        for action, target, result in taken:
            print(f"             -> {action} {target or ''}: {result}")
        print()
    print(f"Tickets:      output/tickets/")
    print(f"Blocklist:    output/blocklist.txt  (pf rules: output/pf_block_rules.conf)")
    print(f"Audit log:    output/response_actions.log")


def main(argv=None):
    p = argparse.ArgumentParser(description="Automated incident response for the Home SOC Lab")
    p.add_argument("--demo", action="store_true", help="use data/sample_alerts.json instead of Splunk")
    p.add_argument("--watch", type=int, metavar="SECONDS", help="keep polling Splunk every N seconds")
    p.add_argument("--reset", action="store_true", help="delete all output (tickets, blocklist, state)")
    args = p.parse_args(argv)

    if args.reset:
        shutil.rmtree(OUT, ignore_errors=True)
        print("Output cleared.")
        return 0

    cfg = load_config()
    os.makedirs(OUT, exist_ok=True)

    if args.watch and not os.environ.get("SPLUNK_PASSWORD") and not args.demo:
        os.environ["SPLUNK_PASSWORD"] = getpass.getpass("Splunk password: ")

    while True:
        state = load_state()
        print(f"\n{datetime.now():%H:%M:%S} Collecting detections from {'sample data' if args.demo else 'Splunk'}...")
        try:
            alerts = fetch_demo() if args.demo else fetch_from_splunk(cfg)
        except SplunkError as e:
            print(f"\nError: {e}")
            return 1
        summary = process(alerts, cfg, state)
        save_state(state)
        print_summary(summary)
        if not args.watch:
            return 0
        print(f"\nWaiting {args.watch}s (Ctrl+C to stop)...")
        try:
            time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 0


if __name__ == "__main__":
    sys.exit(main())

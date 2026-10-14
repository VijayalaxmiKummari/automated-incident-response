"""Run with:  python3 -m unittest discover tests -v"""

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from air.actions import ActionRunner
from air.enrichment import Enricher
from air.playbooks import assess, group_alerts, severity_for
from air.splunk_client import SplunkClient, SplunkError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTEL = os.path.join(ROOT, "data", "threat_intel.csv")
INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def enricher(allowlist=()):
    return Enricher(INTEL, INTERNAL, list(allowlist))


class PlaybookTests(unittest.TestCase):
    def test_alerts_for_same_ip_become_one_incident(self):
        alerts = [
            {"detection": "SSH Brute Force", "result": {"src_ip": "203.0.113.45", "failures": "45"}},
            {"detection": "Successful Login After Brute Force",
             "result": {"src_ip": "203.0.113.45", "compromised_user": "admin"}},
        ]
        incidents = group_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(set(incidents[0]["detections"]),
                         {"SSH Brute Force", "Successful Login After Brute Force"})
        self.assertIn("admin", incidents[0]["users_to_lock"])

    def test_compromise_is_critical_and_blocks(self):
        inc = group_alerts([{"detection": "Successful Login After Brute Force",
                             "result": {"src_ip": "203.0.113.45", "compromised_user": "admin"}}])[0]
        a = assess(inc, enricher().enrich_ip("203.0.113.45"), 60)
        self.assertEqual(a["severity"], "Critical")
        actions = [d[0] for d in a["decisions"]]
        self.assertIn("block_ip", actions)
        self.assertIn("lock_account", actions)
        self.assertIn("notify", actions)

    def test_internal_ip_is_never_blocked(self):
        inc = group_alerts([{"detection": "SQL Injection Attempt", "result": {"clientip": "192.168.1.50"}}])[0]
        a = assess(inc, enricher().enrich_ip("192.168.1.50"), 0)
        actions = [d[0] for d in a["decisions"]]
        self.assertNotIn("block_ip", actions)
        self.assertIn("skip_block", actions)

    def test_allowlisted_external_ip_is_never_blocked(self):
        inc = group_alerts([{"detection": "SSH Brute Force", "result": {"src_ip": "203.0.113.45"}}])[0]
        a = assess(inc, enricher(allowlist=["203.0.113.45"]).enrich_ip("203.0.113.45"), 0)
        self.assertNotIn("block_ip", [d[0] for d in a["decisions"]])

    def test_low_risk_scan_from_unknown_ip_is_not_blocked(self):
        inc = group_alerts([{"detection": "Web Directory Scanning", "result": {"clientip": "8.8.4.4"}}])[0]
        a = assess(inc, enricher().enrich_ip("8.8.4.4"), 60)
        self.assertNotIn("block_ip", [d[0] for d in a["decisions"]])
        self.assertEqual(a["severity"], "Low")

    def test_multivalue_fields_are_handled(self):
        inc = group_alerts([{"detection": "Password Spraying",
                             "result": {"src_ip": ["198.51.100.23"], "usernames": ["root", "test"]}}])[0]
        self.assertEqual(inc["indicator"], "198.51.100.23")

    def test_severity_bands(self):
        self.assertEqual(severity_for(90), "Critical")
        self.assertEqual(severity_for(65), "High")
        self.assertEqual(severity_for(45), "Medium")
        self.assertEqual(severity_for(10), "Low")


class ActionTests(unittest.TestCase):
    def test_block_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            r = ActionRunner(d)
            self.assertIn("added", r.block_ip("203.0.113.45", "INC-1"))
            self.assertEqual(r.block_ip("203.0.113.45", "INC-2"), "already blocked")
            with open(os.path.join(d, "blocklist.txt")) as f:
                self.assertEqual(len(f.readlines()), 1)


class FakeSplunk(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != "Basic YWRtaW46cGFzcw==":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps({"entry": [{"content": {"search": "index=soc_lab | stats count BY src_ip"}}]})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        lines = [
            {"preview": True, "result": {"src_ip": "ignored"}},
            {"preview": False, "result": {"src_ip": "203.0.113.45", "count": "45"}},
            {"preview": False, "result": {"src_ip": "198.51.100.23", "count": "12"}},
        ]
        self.send_response(200)
        self.end_headers()
        self.wfile.write("\n".join(json.dumps(l) for l in lines).encode())


class SplunkClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeSplunk)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def client(self, password="pass"):
        c = SplunkClient("127.0.0.1", self.server.server_port, "admin", password)
        c.base = f"http://127.0.0.1:{self.server.server_port}"  # plain HTTP for the test server
        return c

    def test_reads_saved_search_and_skips_preview_rows(self):
        c = self.client()
        self.assertIn("stats count", c.saved_search_spl("SOC Lab - SSH Brute Force"))
        rows = c.run("index=soc_lab")
        self.assertEqual([r["src_ip"] for r in rows], ["203.0.113.45", "198.51.100.23"])

    def test_wrong_password_gives_clear_error(self):
        with self.assertRaises(SplunkError) as ctx:
            self.client("wrong").saved_search_spl("x")
        self.assertIn("username or password", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

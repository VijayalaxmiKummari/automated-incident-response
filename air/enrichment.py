"""Adds context to an indicator before any decision is made."""

import csv
import ipaddress
import json
import os
from urllib.request import Request, urlopen

DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class Enricher:
    def __init__(self, intel_csv, internal_networks, allowlist):
        self.internal = [ipaddress.ip_network(n) for n in internal_networks]
        self.allowlist = set(allowlist)
        self.intel = {}
        if os.path.exists(intel_csv):
            with open(intel_csv, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    self.intel[row["ip"].strip()] = {
                        "score": int(row["score"]),
                        "tags": [t for t in row["tags"].split(";") if t],
                        "first_seen": row.get("first_seen", ""),
                        "source": row.get("source", "local feed"),
                    }
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")

    def enrich_ip(self, ip):
        info = {"ip": ip, "internal": False, "allowlisted": ip in self.allowlist,
                "documentation_range": False, "reputation": 0, "tags": [], "sources": []}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            info["error"] = "not a valid IP address"
            return info

        info["internal"] = any(addr in net for net in self.internal)
        info["documentation_range"] = any(addr in net for net in DOC_RANGES)

        hit = self.intel.get(ip)
        if hit:
            info["reputation"] = hit["score"]
            info["tags"] = hit["tags"]
            info["first_seen"] = hit["first_seen"]
            info["sources"].append(hit["source"])

        # Optional live lookup. Skipped for internal and documentation addresses.
        if self.abuseipdb_key and not info["internal"] and not info["documentation_range"]:
            live = self._abuseipdb(ip)
            if live is not None:
                info["reputation"] = max(info["reputation"], live["score"])
                info["country"] = live.get("country")
                info["sources"].append("AbuseIPDB")
        return info

    def _abuseipdb(self, ip):
        try:
            req = Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                          headers={"Key": self.abuseipdb_key, "Accept": "application/json"})
            with urlopen(req, timeout=10) as resp:
                data = json.load(resp)["data"]
            return {"score": int(data["abuseConfidenceScore"]), "country": data.get("countryCode")}
        except Exception:
            return None  # enrichment must never stop the response

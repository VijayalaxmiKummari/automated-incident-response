"""Talks to Splunk's REST API (port 8089) using only the Python standard library."""

import base64
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


class SplunkError(Exception):
    pass


class SplunkClient:
    def __init__(self, host, port, username, password, app="soc_lab", verify_tls=False):
        self.base = f"https://{host}:{port}"
        self.app = app
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}"}
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            # A fresh Splunk install uses a self-signed certificate on the management port
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _open(self, path, data=None):
        req = Request(self.base + path, data=data, headers=self.headers)
        try:
            return urlopen(req, context=self.ctx, timeout=120)
        except HTTPError as e:
            if e.code == 401:
                raise SplunkError("Splunk rejected the username or password.") from e
            if e.code == 404:
                raise SplunkError(f"Not found in Splunk: {path}. Is the Home SOC Lab app installed?") from e
            raise SplunkError(f"Splunk returned HTTP {e.code} for {path}") from e
        except URLError as e:
            raise SplunkError(f"Could not reach Splunk at {self.base}. Is Splunk running? ({e.reason})") from e

    def saved_search_spl(self, name):
        """Read the SPL of a saved search, so detections are defined once (in Project 1)."""
        path = f"/servicesNS/-/{self.app}/saved/searches/{quote(name, safe='')}?output_mode=json"
        with self._open(path) as resp:
            body = json.load(resp)
        return body["entry"][0]["content"]["search"]

    def run(self, spl, earliest="-24h", latest="now"):
        """Run a search and return the final result rows as a list of dicts."""
        spl = spl.strip()
        if not spl.startswith("|") and not spl.lower().startswith("search "):
            spl = "search " + spl
        data = urlencode({
            "search": spl,
            "output_mode": "json",
            "earliest_time": earliest,
            "latest_time": latest,
        }).encode()
        rows = []
        with self._open("/services/search/jobs/export", data=data) as resp:
            for line in resp:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("preview"):
                    continue
                if "result" in obj:
                    rows.append(obj["result"])
        return rows

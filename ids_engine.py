"""
ids_engine.py
-------------
Intrusion Detection engine for the mock IEC-104 outstation. Runs on a fixed
cycle (like the 5G testbed's 10-second detectionEngine.js), samples the server's
live counters, computes per-signal rates over the window, and raises severity-
graded alerts: YELLOW / RED / CRITICAL.

Signals (ICS analogues of the 5G doc's NGAP/SCTP/GTP-U signals):
  connection_rate   : new TCP connections/s        -> connection storm (SCTP-like)
  startdt_rate      : STARTDT act/s                 -> activation flood
  apdu_rate         : I+U+S frames/s                -> signalling/APDU flood (NGAP-like)
  malformed_rate    : malformed frames/s            -> junk/crafted flood (GTP-U-like)

Every alert carries the metrics that triggered it, and all cycles are written to
a CSV for offline analysis (matches your "loopback + CSV export" choice).
"""

import time
import csv
import os
from dataclasses import dataclass, field, asdict


# Threshold table: (yellow, red, critical). critical=None means count-based n/a.
DEFAULT_THRESHOLDS = {
    "connection_rate": {"yellow": 5,   "red": 15,   "critical": 40},
    "startdt_rate":    {"yellow": 5,   "red": 20,   "critical": 60},
    "apdu_rate":       {"yellow": 50,  "red": 200,  "critical": 1000},
    "malformed_rate":  {"yellow": 10,  "red": 50,   "critical": 200},
}

SEVERITY_ORDER = {"GREEN": 0, "YELLOW": 1, "RED": 2, "CRITICAL": 3}


@dataclass
class Alert:
    ts: float
    signal: str
    severity: str
    value: float
    threshold: float
    window_s: float
    description: str


class IDSEngine:
    def __init__(self, metrics, cycle_s=2.0, thresholds=None, csv_path=None):
        self.metrics = metrics
        self.cycle_s = cycle_s
        self.thresholds = thresholds or {k: dict(v) for k, v in DEFAULT_THRESHOLDS.items()}
        self.enabled = False
        self._running = False
        self._prev = None
        self._prev_t = None
        self.alerts = []              # capped list, newest last
        self.max_alerts = 200
        self.current = {}             # latest per-signal {value, severity}
        self.csv_path = csv_path
        self._csv_inited = False
        self._on_cycle = None

    # --- lifecycle -----------------------------------------------------------
    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def run_forever(self, stop_flag, on_cycle=None):
        self._running = True
        self._on_cycle = on_cycle
        self._prev = self.metrics.snapshot()
        self._prev_t = time.time()
        while self._running and not stop_flag():
            time.sleep(self.cycle_s)
            self._cycle()

    def stop(self):
        self._running = False

    # --- one detection cycle -------------------------------------------------
    def _cycle(self):
        now = self.metrics.snapshot()
        t = time.time()
        dt = max(1e-6, t - self._prev_t)

        rates = {
            "connection_rate": (now["total_connections"] - self._prev["total_connections"]) / dt,
            "startdt_rate":    (now["startdt_requests"] - self._prev["startdt_requests"]) / dt,
            "apdu_rate":       ((now["i_frames"] + now["u_frames"] + now["s_frames"])
                                - (self._prev["i_frames"] + self._prev["u_frames"] + self._prev["s_frames"])) / dt,
            "malformed_rate":  (now["malformed_frames"] - self._prev["malformed_frames"]) / dt,
        }

        cycle_alerts = []
        current = {}
        for sig, val in rates.items():
            sev, thr = self._grade(sig, val)
            current[sig] = {"value": round(val, 2), "severity": sev, "threshold": thr}
            if sev != "GREEN" and self.enabled:
                a = Alert(ts=t, signal=sig, severity=sev, value=round(val, 2),
                          threshold=thr, window_s=round(dt, 2),
                          description=self._describe(sig, sev, val))
                if not self._is_duplicate(a):
                    self.alerts.append(a)
                    if len(self.alerts) > self.max_alerts:
                        self.alerts.pop(0)
                cycle_alerts.append(a)

        self.current = current
        self._prev, self._prev_t = now, t

        if self.csv_path:
            self._write_csv(t, rates, current)
        if self._on_cycle:
            self._on_cycle(t, rates, current, cycle_alerts, now)

    def _grade(self, signal, value):
        th = self.thresholds[signal]
        if th.get("critical") is not None and value >= th["critical"]:
            return "CRITICAL", th["critical"]
        if value >= th["red"]:
            return "RED", th["red"]
        if value >= th["yellow"]:
            return "YELLOW", th["yellow"]
        return "GREEN", th["yellow"]

    def _describe(self, signal, sev, val):
        names = {
            "connection_rate": "IEC-104 connection storm",
            "startdt_rate": "STARTDT activation flood",
            "apdu_rate": "APDU (I/U/S frame) flood",
            "malformed_rate": "Malformed / junk frame flood",
        }
        return f"{names[signal]} - {sev} at {val:.1f}/s"

    def _is_duplicate(self, alert):
        """Suppress a matching active alert of same signal+severity in last 60s."""
        cutoff = alert.ts - 60
        for a in reversed(self.alerts[:-1]):
            if a.ts < cutoff:
                break
            if a.signal == alert.signal and a.severity == alert.severity:
                return True
        return False

    # --- CSV -----------------------------------------------------------------
    def _write_csv(self, t, rates, current):
        newfile = not self._csv_inited and not os.path.exists(self.csv_path)
        self._csv_inited = True
        with open(self.csv_path, "a", newline="") as f:
            w = csv.writer(f)
            if newfile:
                w.writerow([
                    "timestamp", "iso_time",
                    "connection_rate", "connection_sev",
                    "startdt_rate", "startdt_sev",
                    "apdu_rate", "apdu_sev",
                    "malformed_rate", "malformed_sev",
                    "worst_severity",
                ])
            worst = max(current.values(), key=lambda c: SEVERITY_ORDER[c["severity"]])["severity"]
            w.writerow([
                round(t, 3), time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)),
                round(rates["connection_rate"], 2), current["connection_rate"]["severity"],
                round(rates["startdt_rate"], 2), current["startdt_rate"]["severity"],
                round(rates["apdu_rate"], 2), current["apdu_rate"]["severity"],
                round(rates["malformed_rate"], 2), current["malformed_rate"]["severity"],
                worst,
            ])

    def alert_dicts(self):
        return [asdict(a) for a in self.alerts]

"""
web_app.py
----------
Web app for the IEC-104 DDoS simulation + IDS + defense-in-depth mitigation.
Everything runs in the browser dashboard: attack control, live signal graph,
per-signal severity cards, alerts, mitigation gateway, a recorded-data panel,
and a CSV download of every detection cycle.

Loopback-only. Run, then open http://127.0.0.1:5000.

Run:
    python web_app.py
"""

import io
import csv
import time
import threading
from collections import deque

from flask import Flask, jsonify, request, render_template_string, Response

from mock_iec104_server import MockIEC104Server, ServerMetrics
from attack_engine import AttackEngine
from ids_engine import IDSEngine, SEVERITY_ORDER, DEFAULT_THRESHOLDS
from mitigation import MitigationGateway, MitigationConfig, MitigationStats

app = Flask(__name__)

# --- shared runtime state ----------------------------------------------------
metrics = ServerMetrics()
mit_stats = MitigationStats()
mit_config = MitigationConfig(enabled=False)
gateway = MitigationGateway(config=mit_config, stats=mit_stats)
server = MockIEC104Server(metrics=metrics, gateway=gateway)
attack = AttackEngine()
ids = IDSEngine(metrics, cycle_s=2.0, csv_path="ids_results_web.csv")

HISTORY = deque(maxlen=60)     # rolling window for the live chart
RECORDS = []                   # every detection cycle, for the data panel + CSV
_records_lock = threading.Lock()
_ids_stop = {"v": False}

CSV_COLUMNS = [
    "timestamp", "iso_time",
    "connection_rate", "connection_sev",
    "startdt_rate", "startdt_sev",
    "apdu_rate", "apdu_sev",
    "malformed_rate", "malformed_sev",
    "mitigation", "worst_severity",
]


def _on_cycle(t, rates, current, cycle_alerts, snap):
    worst = max(current.values(), key=lambda c: SEVERITY_ORDER[c["severity"]])["severity"]
    HISTORY.append({
        "t": time.strftime("%H:%M:%S", time.localtime(t)),
        "connection_rate": round(rates["connection_rate"], 1),
        "startdt_rate": round(rates["startdt_rate"], 1),
        "apdu_rate": round(rates["apdu_rate"], 1),
        "malformed_rate": round(rates["malformed_rate"], 1),
        "worst": worst,
    })
    row = {
        "timestamp": round(t, 3),
        "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)),
        "connection_rate": round(rates["connection_rate"], 2),
        "connection_sev": current["connection_rate"]["severity"],
        "startdt_rate": round(rates["startdt_rate"], 2),
        "startdt_sev": current["startdt_rate"]["severity"],
        "apdu_rate": round(rates["apdu_rate"], 2),
        "apdu_sev": current["apdu_rate"]["severity"],
        "malformed_rate": round(rates["malformed_rate"], 2),
        "malformed_sev": current["malformed_rate"]["severity"],
        "mitigation": "ON" if mit_config.enabled else "OFF",
        "worst_severity": worst,
    }
    with _records_lock:
        RECORDS.append(row)


def _boot():
    server.start()
    ids.enable()
    threading.Thread(
        target=ids.run_forever, args=(lambda: _ids_stop["v"], _on_cycle),
        daemon=True).start()


# --- API ---------------------------------------------------------------------
@app.route("/api/state")
def api_state():
    with _records_lock:
        recent = RECORDS[-40:][::-1]     # newest first for the panel
        total = len(RECORDS)
    return jsonify({
        "ids_enabled": ids.enabled,
        "current": ids.current,
        "history": list(HISTORY),
        "alerts": ids.alert_dicts()[-25:][::-1],
        "attack": attack.stats(),
        "server": metrics.snapshot(),
        "thresholds": ids.thresholds,
        "mitigation_enabled": mit_config.enabled,
        "mitigation": mit_stats.snapshot(),
        "records": recent,
        "record_count": total,
        "columns": CSV_COLUMNS,
    })


@app.route("/api/data.csv")
def api_data_csv():
    """Download every recorded detection cycle as a CSV file."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    w.writeheader()
    with _records_lock:
        for r in RECORDS:
            w.writerow(r)
    fname = time.strftime("iec104_ids_%Y%m%d_%H%M%S.csv")
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/data/clear", methods=["POST"])
def api_data_clear():
    with _records_lock:
        RECORDS.clear()
    return jsonify({"cleared": True})


@app.route("/api/mitigation/toggle", methods=["POST"])
def api_mitigation_toggle():
    mit_config.enabled = not mit_config.enabled
    return jsonify({"mitigation_enabled": mit_config.enabled})


@app.route("/api/attack/start", methods=["POST"])
def api_attack_start():
    d = request.get_json(force=True)
    profile = d.get("profile", "apdu_flood")
    burst = int(d.get("burst", 200))
    duration = float(d.get("duration", 0.5))
    wait = float(d.get("wait", 1.0))
    # guardrails: keep it bounded even from the UI
    burst = max(1, min(burst, 1000))
    duration = max(0.1, min(duration, 30))
    wait = max(0.2, min(wait, 10))
    ok = attack.start(profile, burst, duration, wait)
    return jsonify({"started": ok})


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    attack.stop()
    return jsonify({"stopped": True})


@app.route("/api/ids/toggle", methods=["POST"])
def api_ids_toggle():
    if ids.enabled:
        ids.disable()
    else:
        ids.enable()
    return jsonify({"ids_enabled": ids.enabled})


@app.route("/")
def index():
    return render_template_string(PAGE), 200, {"Content-Type": "text/html; charset=utf-8"}


# --- template loaded from separate file to keep this readable ---------------
with open("dashboard.html", "r", encoding="utf-8") as _f:
    PAGE = _f.read()


if __name__ == "__main__":
    _boot()
    print("Dashboard: http://127.0.0.1:5000  (loopback only)")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

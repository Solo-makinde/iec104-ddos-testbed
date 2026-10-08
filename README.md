# IEC 60870-5-104 DDoS Simulation, IDS & Mitigation Testbed (Web App)

A self-contained, **loopback-only** web app that simulates a DDoS attack against a
SCADA/ICS outstation speaking **IEC 60870-5-104** (the TCP profile used in energy
SCADA), detects it with an intrusion-detection engine, and defends against it with a
defense-in-depth mitigation gateway. Mirrors the IEEE 5G testbed (attack -> detect ->
defend) but for ICS protocols.

Everything happens in the browser dashboard: launch attacks, watch the IDS classify
them live, toggle mitigation, view a recorded-data panel, and download a CSV.

## Safety by design

- The mock outstation binds to **127.0.0.1 only**; the attack engine only ever
  connects to `127.0.0.1`. There is no mode that targets an external IP.
- All attacks are **time-bounded** and auto-complete at the configured duration.

## Files

| File | Role |
|---|---|
| `web_app.py` | Flask app: attack control, IDS, mitigation, data recording, CSV download |
| `dashboard.html` | Dashboard UI (graph, cards, alerts, mitigation, data panel) |
| `mock_iec104_server.py` | Mock IEC-104 outstation; parses APCI frames, exposes counters |
| `attack_engine.py` | Burst-based attack simulator (3 profiles), loopback-locked |
| `ids_engine.py` | Detection engine: per-signal rates, severity grading, dedup |
| `mitigation.py` | Defense-in-depth gateway (4 DDoS controls) |

## Requirements

- Python 3.8+
- `pip install flask`

## Run

```bash
pip install flask
python web_app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Using the dashboard

1. **Attack Control** - pick a profile, set burst / duration / wait, hit **Start**.
2. **Severity cards + live graph** - each signal's rate and severity
   (GREEN / YELLOW / RED / CRITICAL) updates every 2 seconds.
3. **Mitigation** - click **Mitigation: OFF/ON**. Run the same attack off, then on,
   and compare; the mitigation panel counts blocked vs allowed traffic live.
4. **Recorded Data panel** - every detection cycle is appended as a row (with a
   Mit ON/OFF column). **Download CSV** for a timestamped file, or **Clear** to reset.

## Attack profiles (ICS analogues of the 5G doc's vectors)

| Profile | What it does | Trips signal | 5G-doc analogue |
|---|---|---|---|
| `connection_flood` | TCP connection + STARTDT storms | connection / startdt | SCTP rogue-gNB flood |
| `apdu_flood` | I/U/S frame flood on one connection | apdu | NGAP registration flood |
| `malformed_flood` | Junk / bad-APCI frames | malformed | crafted-packet flood |

## Detection signals & default thresholds

| Signal | YELLOW | RED | CRITICAL |
|---|---|---|---|
| `connection_rate` | 5/s | 15/s | 40/s |
| `startdt_rate` | 5/s | 20/s | 60/s |
| `apdu_rate` | 50/s | 200/s | 1000/s |
| `malformed_rate` | 10/s | 50/s | 200/s |

Editable in `ids_engine.py` (`DEFAULT_THRESHOLDS`).

## Mitigation gateway (four DDoS controls)

Implements the paper's DDoS mitigation set ("boundary filtering, rate controls,
connection thresholds, and protocol-aware traffic inspection"):

| Control | Blocks | Paper mapping |
|---|---|---|
| Source allowlist (default-deny) | non-approved sources | boundary filtering / ICS DMZ |
| Connection-rate threshold | connection storms | connection thresholds |
| Frame-rate limiter (token bucket) | APDU floods | rate controls |
| Protocol-aware inspection | malformed / junk frames | protocol-aware inspection |

Representative before/after (toggle mitigation, re-run same attack):

| Attack | Mit OFF | Mit ON |
|---|---|---|
| APDU flood | RED | YELLOW |
| Connection storm | RED | YELLOW |
| Malformed flood | CRITICAL | GREEN |

## CSV output

- **Download CSV** button - all recorded rows, timestamped filename.
- On disk - the app also streams cycles to `ids_results_web.csv` in the run folder.

Columns: timestamp, ISO time, each signal's rate + severity, mitigation state, worst
severity. Drop into pandas / Excel to chart the attack -> detect -> mitigate timeline.

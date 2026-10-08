"""
run_cli.py
----------
Terminal front-end for the IEC-104 DDoS simulation. Boots the mock outstation,
enables the IDS, launches an attack, and prints a live per-signal status board
(GREEN/YELLOW/RED/CRITICAL) each detection cycle. Writes results to CSV.

Everything is loopback-only and time-bounded.

Usage:
    python run_cli.py --profile apdu_flood --burst 300 --duration 0.5 --wait 1
    python run_cli.py --profile connection_flood --burst 25 --duration 0.5 --wait 1
    python run_cli.py --profile malformed_flood --burst 120 --duration 0.5 --wait 1
"""

import argparse
import time
import threading

from mock_iec104_server import MockIEC104Server, ServerMetrics
from attack_engine import AttackEngine
from ids_engine import IDSEngine, SEVERITY_ORDER

COLORS = {
    "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "RED": "\033[91m", "CRITICAL": "\033[95m",
}
RESET = "\033[0m"


def color(sev):
    return f"{COLORS.get(sev,'')}{sev:<8}{RESET}"


def main():
    ap = argparse.ArgumentParser(description="IEC-104 DDoS simulation (loopback only)")
    ap.add_argument("--profile", default="apdu_flood",
                    choices=["connection_flood", "apdu_flood", "malformed_flood"])
    ap.add_argument("--burst", type=int, default=200, help="frames/connections per burst")
    ap.add_argument("--duration", type=float, default=0.5, help="minutes")
    ap.add_argument("--wait", type=float, default=1.0, help="seconds between bursts")
    ap.add_argument("--cycle", type=float, default=2.0, help="IDS cycle seconds")
    ap.add_argument("--csv", default="ids_results.csv")
    ap.add_argument("--port", type=int, default=2404)
    args = ap.parse_args()

    metrics = ServerMetrics()
    server = MockIEC104Server(port=args.port, metrics=metrics)
    server.start()
    print(f"[server] mock IEC-104 outstation on 127.0.0.1:{args.port} (loopback only)")

    ids = IDSEngine(metrics, cycle_s=args.cycle, csv_path=args.csv)
    ids.enable()

    stop = {"v": False}

    def on_cycle(t, rates, current, cycle_alerts, snap):
        line = " | ".join(
            f"{sig.replace('_rate',''):<11} {rates[sig]:6.1f}/s {color(current[sig]['severity'])}"
            for sig in ["connection_rate", "startdt_rate", "apdu_rate", "malformed_rate"]
        )
        worst = max(current.values(), key=lambda c: SEVERITY_ORDER[c["severity"]])["severity"]
        print(f"[ids {time.strftime('%H:%M:%S')}] {line}  => worst {color(worst)}")

    ids_thread = threading.Thread(
        target=ids.run_forever, args=(lambda: stop["v"], on_cycle), daemon=True)
    ids_thread.start()

    print(f"[attack] profile={args.profile} burst={args.burst} "
          f"duration={args.duration}min wait={args.wait}s")
    print("-" * 92)

    attack = AttackEngine(target_port=args.port)
    attack.start(args.profile, args.burst, args.duration, args.wait)

    try:
        while attack.stats()["state"] == "RUNNING":
            time.sleep(0.5)
    except KeyboardInterrupt:
        attack.stop()

    # let IDS catch the tail, then stop
    time.sleep(args.cycle * 2)
    stop["v"] = True
    ids.stop()
    server.stop()

    st = attack.stats()
    print("-" * 92)
    print(f"[attack] COMPLETED  frames_sent={st['frames_sent']} "
          f"bytes_sent={st['bytes_sent']} bursts={st['bursts']} "
          f"connections={st['connections_opened']} errors={st['errors']}")
    print(f"[server] {metrics.snapshot()}")
    print(f"[ids] total alerts raised: {len(ids.alerts)}")
    sev_counts = {}
    for a in ids.alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
    print(f"[ids] alert breakdown: {sev_counts}")
    print(f"[csv] results written to {args.csv}")


if __name__ == "__main__":
    main()

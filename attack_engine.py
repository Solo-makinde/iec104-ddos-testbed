"""
attack_engine.py
----------------
Burst-based DDoS *simulation* against the local mock IEC-104 outstation.
Mirrors the 5G testbed's Scapy attack model (burst_rate / duration / wait_period)
but is hard-locked to 127.0.0.1 so it cannot generate traffic on any real network.

Three attack profiles, each an ICS analogue of the 5G doc's three vectors:
  - "connection_flood"  : STARTDT connection storm      (~ SCTP rogue-gNB flood)
  - "apdu_flood"        : rapid I/U frame injection       (~ NGAP registration flood)
  - "malformed_flood"   : junk bytes / bad APCI headers   (~ crafted-packet flood)

Every attack builds REAL protocol-accurate IEC-104 bytes so the mock server's
parser and the IDS see authentic frame patterns.
"""

import socket
import time
import threading
import struct

LOOPBACK = "127.0.0.1"
START_BYTE = 0x68

# U-frame control fields
U_STARTDT_ACT = 0x07
U_TESTFR_ACT  = 0x43


def _apci_u(control0):
    """Build a 6-byte U-frame APCI."""
    return bytes([START_BYTE, 4, control0, 0, 0, 0])


def _apci_i(tx_seq, rx_seq, asdu=b""):
    """Build an I-frame: 6-byte APCI carrying send/recv sequence numbers + ASDU."""
    length = 4 + len(asdu)
    txf = (tx_seq << 1) & 0xFFFF          # LSB=0 marks I-frame
    rxf = (rx_seq << 1) & 0xFFFF
    ctrl = struct.pack("<HH", txf, rxf)
    return bytes([START_BYTE, length]) + ctrl + asdu


class AttackEngine:
    def __init__(self, target_port=2404):
        self.target_port = target_port
        self._running = False
        self._stats = {
            "state": "IDLE",
            "profile": None,
            "frames_sent": 0,
            "bytes_sent": 0,
            "bursts": 0,
            "connections_opened": 0,
            "errors": 0,
            "started_at": None,
            "ends_at": None,
        }
        self._lock = threading.Lock()
        self._thread = None

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def stop(self):
        self._running = False

    def start(self, profile, burst_rate, duration_min, wait_period_s, on_tick=None):
        """
        profile        : one of connection_flood | apdu_flood | malformed_flood
        burst_rate     : frames (or connections) per burst   [1-1000 here]
        duration_min   : total minutes before auto-stop
        wait_period_s  : seconds to sleep between bursts
        on_tick        : optional callback(stats_dict) after each burst
        """
        if self._running:
            return False
        self._running = True
        with self._lock:
            self._stats.update({
                "state": "RUNNING", "profile": profile, "frames_sent": 0,
                "bytes_sent": 0, "bursts": 0, "connections_opened": 0,
                "errors": 0, "started_at": time.time(),
                "ends_at": time.time() + duration_min * 60,
            })
        self._thread = threading.Thread(
            target=self._run, args=(profile, burst_rate, duration_min,
                                    wait_period_s, on_tick), daemon=True)
        self._thread.start()
        return True

    def _run(self, profile, burst_rate, duration_min, wait_period_s, on_tick):
        end_time = time.time() + duration_min * 60
        try:
            while self._running and time.time() < end_time:
                if profile == "connection_flood":
                    self._connection_burst(burst_rate)
                elif profile == "apdu_flood":
                    self._apdu_burst(burst_rate)
                elif profile == "malformed_flood":
                    self._malformed_burst(burst_rate)
                with self._lock:
                    self._stats["bursts"] += 1
                if on_tick:
                    on_tick(self.stats())
                # sleep in small slices so stop() is responsive
                slept = 0.0
                while slept < wait_period_s and self._running and time.time() < end_time:
                    time.sleep(min(0.1, wait_period_s - slept))
                    slept += 0.1
        finally:
            with self._lock:
                self._stats["state"] = "COMPLETED"

    # --- attack profiles -----------------------------------------------------
    def _connection_burst(self, n):
        """Open n TCP connections and fire STARTDT act on each (connection storm)."""
        for _ in range(n):
            if not self._running:
                break
            try:
                s = socket.create_connection((LOOPBACK, self.target_port), timeout=1.0)
                with self._lock:
                    self._stats["connections_opened"] += 1
                frame = _apci_u(U_STARTDT_ACT)
                s.sendall(frame)
                self._count(frame)
                s.close()
            except OSError:
                with self._lock:
                    self._stats["errors"] += 1

    def _apdu_burst(self, n):
        """One connection, hammer it with n I-frames + TESTFR (APDU flood)."""
        try:
            s = socket.create_connection((LOOPBACK, self.target_port), timeout=1.0)
            with self._lock:
                self._stats["connections_opened"] += 1
            for i in range(n):
                if not self._running:
                    break
                if i % 5 == 0:
                    frame = _apci_u(U_TESTFR_ACT)
                else:
                    frame = _apci_i(tx_seq=i, rx_seq=0, asdu=b"\x41" * 12)
                try:
                    s.sendall(frame)
                    self._count(frame)
                except OSError:
                    with self._lock:
                        self._stats["errors"] += 1
                    break
            s.close()
        except OSError:
            with self._lock:
                self._stats["errors"] += 1

    def _malformed_burst(self, n):
        """Fire n junk / bad-APCI frames to exercise malformed-frame detection."""
        try:
            s = socket.create_connection((LOOPBACK, self.target_port), timeout=1.0)
            with self._lock:
                self._stats["connections_opened"] += 1
            for _ in range(n):
                if not self._running:
                    break
                # wrong start byte + random length: server counts as malformed
                frame = bytes([0x99, 0x04, 0xFF, 0xFF, 0xFF, 0xFF])
                try:
                    s.sendall(frame)
                    self._count(frame)
                except OSError:
                    with self._lock:
                        self._stats["errors"] += 1
                    break
            s.close()
        except OSError:
            with self._lock:
                self._stats["errors"] += 1

    def _count(self, frame):
        with self._lock:
            self._stats["frames_sent"] += 1
            self._stats["bytes_sent"] += len(frame)

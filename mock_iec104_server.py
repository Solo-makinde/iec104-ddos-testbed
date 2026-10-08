"""
mock_iec104_server.py
---------------------
A deliberately simplified, SAFE mock of an IEC 60870-5-104 (IEC-104) outstation
(the "RTU/PLC" side). It ONLY binds to 127.0.0.1 so it can never receive traffic
from a real network. It exists purely so the attack simulator has something local
to talk to, exactly like the mock AMF/UPF in the 5G testbed.

IEC-104 basics modeled here (enough to be realistic, not enough to touch real gear):
  - APCI (Application Protocol Control Information): 6-byte header starting 0x68
  - Frame formats: I (information), S (supervisory), U (unnumbered control)
  - U-frame control functions: STARTDT / STOPDT / TESTFR (act/con)
The server tracks connection state and per-connection frame counts so the IDS
has real counters to read, mirroring how Open5GS exposes Prometheus metrics.
"""

import socket
import threading
import time
import struct
from dataclasses import dataclass, field
from collections import defaultdict

LOOPBACK = "127.0.0.1"

# ---- IEC-104 constants (subset) --------------------------------------------
START_BYTE = 0x68

# U-frame control field bit patterns (first control octet), act/con pairs
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT  = 0x13
U_STOPDT_CON  = 0x23
U_TESTFR_ACT  = 0x43
U_TESTFR_CON  = 0x83


@dataclass
class ServerMetrics:
    """Live counters the IDS will sample every cycle (like Prometheus counters)."""
    total_connections: int = 0
    active_connections: int = 0
    i_frames: int = 0            # information frames received
    s_frames: int = 0            # supervisory frames received
    u_frames: int = 0            # unnumbered control frames received
    startdt_requests: int = 0    # STARTDT act received (connection activation storms)
    testfr_requests: int = 0     # TESTFR act received (keepalive storms)
    malformed_frames: int = 0    # frames that failed to parse (junk floods)
    bytes_received: int = 0
    # per-source-port connection attempts, to spot a single hammering source
    conn_attempts_by_src: dict = field(default_factory=lambda: defaultdict(int))
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self):
        with self.lock:
            return {
                "total_connections": self.total_connections,
                "active_connections": self.active_connections,
                "i_frames": self.i_frames,
                "s_frames": self.s_frames,
                "u_frames": self.u_frames,
                "startdt_requests": self.startdt_requests,
                "testfr_requests": self.testfr_requests,
                "malformed_frames": self.malformed_frames,
                "bytes_received": self.bytes_received,
                "distinct_sources": len(self.conn_attempts_by_src),
            }


class MockIEC104Server:
    def __init__(self, port=2404, metrics=None, gateway=None):
        # 2404 is the real IANA port for IEC-104; safe here because loopback-only
        self.port = port
        self.metrics = metrics or ServerMetrics()
        self.gateway = gateway   # optional MitigationGateway; None = no mitigation
        self._sock = None
        self._running = False
        self._threads = []

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # HARD SAFETY: bind loopback only. Never 0.0.0.0.
        self._sock.bind((LOOPBACK, self.port))
        self._sock.listen(128)
        self._sock.settimeout(0.5)
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # mitigation: connection admission (allowlist + conn-rate threshold)
            if self.gateway is not None:
                allowed, reason = self.gateway.admit_connection(addr[0], addr[1])
                if not allowed:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            with self.metrics.lock:
                self.metrics.total_connections += 1
                self.metrics.active_connections += 1
                self.metrics.conn_attempts_by_src[addr[1]] += 1
            ct = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            ct.start()
            self._threads.append(ct)

    def _handle_conn(self, conn):
        conn.settimeout(1.0)
        buf = b""
        limiter = self.gateway.new_frame_limiter() if self.gateway is not None else None
        try:
            while self._running:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                with self.metrics.lock:
                    self.metrics.bytes_received += len(data)
                buf += data
                buf = self._parse_frames(conn, buf, limiter)
        finally:
            with self.metrics.lock:
                self.metrics.active_connections = max(0, self.metrics.active_connections - 1)
            try:
                conn.close()
            except OSError:
                pass

    def _parse_frames(self, conn, buf, limiter=None):
        """Parse as many complete IEC-104 APCIs as are in buf; return leftover."""
        while len(buf) >= 2:
            if buf[0] != START_BYTE:
                # not a valid IEC-104 start -> junk/malformed flood
                # mitigation: protocol inspection drops it at the gateway before
                # the outstation ever counts it
                if self.gateway is not None and not self.gateway.admit_frame(buf[:6], limiter):
                    buf = buf[1:]
                    continue
                with self.metrics.lock:
                    self.metrics.malformed_frames += 1
                buf = buf[1:]  # resync by dropping one byte
                continue
            length = buf[1]  # APDU length field
            if length < 4:
                if self.gateway is not None and not self.gateway.admit_frame(buf[:6], limiter):
                    buf = buf[2:]
                    continue
                with self.metrics.lock:
                    self.metrics.malformed_frames += 1
                buf = buf[2:]
                continue
            total = 2 + length
            if len(buf) < total:
                break  # wait for more bytes
            frame = buf[:total]
            buf = buf[total:]
            # mitigation: rate limit + protocol inspection on well-formed frames
            if self.gateway is not None and not self.gateway.admit_frame(frame, limiter):
                continue  # dropped at gateway, never reaches the outstation
            self._classify_frame(conn, frame)
        return buf

    def _classify_frame(self, conn, frame):
        # control field = 4 octets after the 2-byte start/length
        cf = frame[2:6]
        c0 = cf[0]
        with self.metrics.lock:
            if c0 & 0x01 == 0:          # I-frame (LSB of first octet = 0)
                self.metrics.i_frames += 1
            elif c0 & 0x03 == 0x01:     # S-frame (bits = 01)
                self.metrics.s_frames += 1
            else:                        # U-frame (bits = 11)
                self.metrics.u_frames += 1
                if c0 == U_STARTDT_ACT:
                    self.metrics.startdt_requests += 1
                    self._reply(conn, U_STARTDT_CON)
                elif c0 == U_TESTFR_ACT:
                    self.metrics.testfr_requests += 1
                    self._reply(conn, U_TESTFR_CON)
                elif c0 == U_STOPDT_ACT:
                    self._reply(conn, U_STOPDT_CON)

    def _reply(self, conn, control0):
        # minimal U-frame response: 68 04 <c0> 00 00 00
        frame = bytes([START_BYTE, 4, control0, 0, 0, 0])
        try:
            conn.sendall(frame)
        except OSError:
            pass

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    m = ServerMetrics()
    srv = MockIEC104Server(metrics=m)
    srv.start()
    print(f"Mock IEC-104 outstation listening on {LOOPBACK}:{srv.port} (loopback only)")
    try:
        while True:
            time.sleep(2)
            print(m.snapshot())
    except KeyboardInterrupt:
        srv.stop()
        print("stopped")

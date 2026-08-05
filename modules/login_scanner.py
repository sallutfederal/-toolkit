import re
import requests
from urllib.parse import urlparse
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("login_scanner")


class LoginScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def get_domain(self, user_input):
        if not user_input.startswith("http"):
            user_input = "https://" + user_input
        parsed = urlparse(user_input)
        domain = parsed.netloc
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def scan_endpoints(self, domain):
        endpoints = []
        common_paths = [
            "/login", "/signin", "/auth", "/log-in", "/sign-in",
            "/account/login", "/user/login", "/admin/login",
            "/oauth", "/auth/login", "/sso", "/saml",
        ]
        for path in common_paths:
            url = f"https://{domain}{path}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code < 400:
                    endpoints.append({"url": url, "status": response.status_code})
            except Exception:
                pass
        return endpoints

    def analyze_forms(self, url):
        fields = []
        try:
            response = self.session.get(url, timeout=10)
            html = response.text

            for match in re.finditer(
                r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', html, re.IGNORECASE
            ):
                field = match.group(1)
                if any(k in field.lower() for k in ["user", "email", "login", "usuario"]):
                    fields.append({"name": field, "type": "text"})

            for match in re.finditer(
                r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']*)["\'][^>]*>',
                html, re.IGNORECASE
            ):
                fields.append({"name": match.group(1), "type": "password"})

            for match in re.finditer(
                r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*>',
                html, re.IGNORECASE
            ):
                fields.append({"name": match.group(1), "type": "hidden"})
        except Exception:
            pass
        return fields

    def check_security_headers(self, domain):
        headers = {}
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            for header in [
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
            ]:
                headers[header] = "presente" if header in response.headers else "ausente"
        except Exception:
            pass
        return headers

    def generate_report(self, domain, endpoints, fields, headers):
        report = []
        report.append("═══════════════════════════════════════════")
        report.append("  SECURITY ASSESSMENT REPORT")
        report.append("═══════════════════════════════════════════")
        report.append(f"  Target: {domain}")
        report.append(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("═══════════════════════════════════════════")
        report.append("")

        report.append("▸ LOGIN ENDPOINTS")
        if endpoints:
            for ep in endpoints:
                report.append(f"  [{ep['status']}] {ep['url']}")
        else:
            report.append("  Nenhum endpoint encontrado")
        report.append("")

        report.append("▸ FORM FIELDS")
        if fields:
            for field in fields:
                report.append(f"  {field['name']} ({field['type']})")
        else:
            report.append("  Nenhum campo encontrado")
        report.append("")

        report.append("▸ SECURITY HEADERS")
        if headers:
            for header, status in headers.items():
                icon = "+" if status == "presente" else "-"
                report.append(f"  [{icon}] {header}: {status}")
        else:
            report.append("  Nao foi possivel verificar")
        report.append("")

        report.append("▸ RECOMMENDATIONS")
        report.append("  - Implementar rate limiting nos endpoints de login")
        report.append("  - Adicionar CAPTCHA apos 3 tentativas")
        report.append("  - Considerar autenticacao em dois fatores")

        return "\n".join(report)

    def scan(self, target):
        domain = self.get_domain(target)
        endpoints = self.scan_endpoints(domain)
        fields = self.analyze_forms(f"https://{domain}")
        headers = self.check_security_headers(domain)
        report = self.generate_report(domain, endpoints, fields, headers)
        return {
            "domain": domain,
            "endpoints": endpoints,
            "fields": fields,
            "headers": headers,
            "report": report,
        }


def run(config=None):
    if config is None:
        config = {}
    target = config.get("target", "")
    if not target:
        raise ValueError("Target is required")
    scanner = LoginScanner()
    return scanner.scan(target)

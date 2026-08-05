import re
import json
import csv
import os
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from utils.logger import get_module_logger

logger = get_module_logger("credential_harvester")


LOGIN_FORM_PATTERNS = {
    "username_field": [
        r"username", r"user", r"login", r"email", r"user_id",
        r"user_name", r"account", r"userid", r"login_id",
    ],
    "password_field": [
        r"password", r"pass", r"pwd", r"passwd", r"secret",
        r"confirm_password", r"new_password", r"current_password",
    ],
    "mfa_field": [
        r"mfa", r"otp", r"2fa", r"two.factor", r"verification",
        r"code", r"token", r"pin", r"security.code",
    ],
    "csrf_token": [
        r"csrf", r"token", r"_token", r"authenticity_token",
        r"_csrf", r"csrfmiddlewaretoken",
    ],
}


COMMON_LOGIN_URLS = [
    "/login", "/signin", "/auth/login", "/auth/signin",
    "/admin/login", "/portal/login", "/vpn/login", "/ssso/login",
    "/oauth/authorize", "/saml/login", "/cas/login",
    "/wp-login.php", "/administrator", "/manager/html",
    "/webconsole", "/ui/login", "/auth",
]


def _extract_form_fields(html_content):
    fields = []
    field_patterns = [
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?([^"\'\s>]+)',
        r'<input[^>]*type=["\']?([^"\'\s>]+)["\'][^>]*name=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']([^"\']+)["\']',
    ]
    for pattern in field_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            field_name = match.group(1) if match.lastindex >= 1 else match.group(2)
            field_type = match.group(2) if match.lastindex >= 2 else "text"
            fields.append({"name": field_name, "type": field_type.lower()})
    return fields


def _classify_field(field_name, field_type):
    field_lower = field_name.lower()
    field_type_lower = field_type.lower()

    classification = {"field_name": field_name, "field_type": field_type, "category": "unknown"}

    for category, patterns in LOGIN_FORM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, field_lower, re.IGNORECASE):
                classification["category"] = category
                return classification

    if field_type_lower in ("password", "passwd"):
        classification["category"] = "password_field"
    elif field_type_lower in ("text", "email", "username"):
        classification["category"] = "username_field"

    return classification


def parse_login_form(html_content, page_url=""):
    fields = _extract_form_fields(html_content)
    classified = [_classify_field(f["name"], f["type"]) for f in fields]

    form_action = ""
    action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if action_match:
        form_action = action_match.group(1)
        if not form_action.startswith("http"):
            parsed_url = urlparse(page_url)
            base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            form_action = base + form_action

    csrf_tokens = [f for f in classified if f["category"] == "csrf_token"]
    username_fields = [f for f in classified if f["category"] == "username_field"]
    password_fields = [f for f in classified if f["category"] == "password_field"]
    mfa_fields = [f for f in classified if f["category"] == "mfa_field"]

    return {
        "page_url": page_url,
        "form_action": form_action,
        "fields": classified,
        "username_fields": username_fields,
        "password_fields": password_fields,
        "mfa_fields": mfa_fields,
        "csrf_tokens": csrf_tokens,
        "field_count": len(classified),
        "has_login_form": len(username_fields) > 0 and len(password_fields) > 0,
        "timestamp": datetime.now().isoformat(),
    }


def extract_credentials_from_url(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    sensitive_params = {}
    for key, values in query_params.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in ["user", "login", "email", "pass", "pwd", "token", "key", "secret"]):
            sensitive_params[key] = values[0]

    return {
        "url": url,
        "sensitive_params": sensitive_params,
        "param_count": len(sensitive_params),
    }


def analyze_form_page(html_content, page_url="", output_file=None):
    result = parse_login_form(html_content, page_url)

    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("LOGIN FORM ANALYSIS REPORT")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 70)
    report_lines.append(f"Page URL: {page_url or 'N/A'}")
    report_lines.append(f"Form Action: {result['form_action'] or 'N/A'}")
    report_lines.append(f"Total Fields: {result['field_count']}")
    report_lines.append(f"Login Form Detected: {result['has_login_form']}")
    report_lines.append("")

    if result["username_fields"]:
        report_lines.append("Username Fields:")
        for f in result["username_fields"]:
            report_lines.append(f"  - {f['field_name']} (type: {f['field_type']})")

    if result["password_fields"]:
        report_lines.append("Password Fields:")
        for f in result["password_fields"]:
            report_lines.append(f"  - {f['field_name']} (type: {f['field_type']})")

    if result["mfa_fields"]:
        report_lines.append("MFA Fields:")
        for f in result["mfa_fields"]:
            report_lines.append(f"  - {f['field_name']} (type: {f['field_type']})")

    if result["csrf_tokens"]:
        report_lines.append("CSRF Tokens:")
        for f in result["csrf_tokens"]:
            report_lines.append(f"  - {f['field_name']}")

    report_lines.append("")
    report_lines.append("All Fields:")
    for f in result["fields"]:
        report_lines.append(f"  [{f['category']}] {f['field_name']} (type: {f['field_type']})")

    report = "\n".join(report_lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Form analysis report saved to %s", output_file)

    return result


def scan_for_login_pages(html_pages):
    results = []
    for url, html in html_pages.items():
        analysis = parse_login_form(html, url)
        if analysis["has_login_form"]:
            results.append(analysis)
            logger.info("Login form found at %s", url)
    return results


def export_results(results, output_file, format="json"):
    if format == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
    elif format == "csv":
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "form_action", "has_login_form", "field_count", "username_fields", "password_fields", "mfa_fields"])
            for r in results:
                writer.writerow([
                    r.get("page_url", ""),
                    r.get("form_action", ""),
                    r.get("has_login_form", False),
                    r.get("field_count", 0),
                    len(r.get("username_fields", [])),
                    len(r.get("password_fields", [])),
                    len(r.get("mfa_fields", [])),
                ])
    logger.info("Results exported to %s (%s)", output_file, format)


def run(config=None):
    if config is None:
        config = {}

    mode = config.get("mode", "parse")
    html_content = config.get("html_content", "")
    page_url = config.get("page_url", "")
    html_pages = config.get("html_pages", {})
    url = config.get("url", "")
    output_file = config.get("output_file", None)

    logger.info("Credential Harvester Module starting...")
    logger.info("Mode: %s", mode)

    if mode == "parse":
        result = parse_login_form(html_content, page_url)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
        return result

    elif mode == "scan":
        results = scan_for_login_pages(html_pages)
        if output_file:
            export_results(results, output_file)
        return results

    elif mode == "extract_url":
        result = extract_credentials_from_url(url)
        return result

    elif mode == "analyze":
        return analyze_form_page(html_content, page_url, output_file)

    else:
        raise ValueError(f"Unknown mode: {mode}")


if __name__ == "__main__":
    run()
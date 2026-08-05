import smtplib
import ssl
import os
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("email_campaign")


URL_OBFUSCATION_TECHNIQUES = {
    "hex_encode": lambda url: "0x" + "".join(f"{ord(c):02x}" for c in url),
    "entity_encode": lambda url: "".join(f"&#{ord(c)};" for c in url),
    "base64": lambda url: __import__("base64").b64encode(url.encode()).decode(),
    "redirect_chain": lambda url: f"http://{random.choice(['track.', 'cdn.', 'metrics.', 'analytics.', 'assets.'])}{random.choice(['example.com', 'test.local', 'internal.net'])}/{''.join(random.choices(string.ascii_lowercase, k=8))}?u={url}",
    "homograph": lambda url: url.replace("a", "а").replace("o", "о").replace("e", "е"),
}

EMAIL_TEMPLATES = {
    "phishing_credential": {
        "subject": "Action Required: Verify Your Account Immediately",
        "body": """Dear {name},

We detected unusual activity on your {service} account. For your security,
you must verify your identity within 24 hours to prevent account suspension.

Click here to verify: {link}

If you do not complete verification within 24 hours, your account will be
temporarily locked and you will need to contact support.

Regards,
{brand} Security Team""",
    },
    "phishing_invoice": {
        "subject": "Invoice #{invoice_id} - Payment Required",
        "body": """Dear {name},

Please find attached invoice #{invoice_id} for services rendered.
Total amount due: ${amount}

Payment is due within 5 business days. Click below to view and pay:
{link}

If you have already submitted payment, please disregard this notice.

Regards,
Accounts Department""",
    },
    "phishing_document": {
        "subject": "Document Review Required - {doc_name}",
        "body": """Hi {name},

A document has been shared with you for review. Please review and
provide feedback at your earliest convenience.

Access the document here: {link}

This is an automated notification. Please do not reply to this email.

Best regards,
Document Management System""",
    },
    "phishing_it_alert": {
        "subject": "IT Security Alert: Password Expiration Notice",
        "body": """Dear {name},

Your corporate password will expire in 48 hours. You must change it
before expiration to maintain access to all company systems.

Change your password now: {link}

If you have recently changed your password, you can safely ignore
this notification.

IT Security Team""",
    },
}


def _generate_placeholder_data(pattern_type):
    data = {
        "name": random.choice([
            "John Smith", "Maria Garcia", "David Chen", "Sarah Johnson",
            "Robert Williams", "Lisa Anderson", "Michael Brown", "Emma Davis",
        ]),
        "service": random.choice(["Office 365", "VPN", "Email", "Corporate Portal", "Cloud Storage"]),
        "brand": random.choice(["TechCorp", "SecureNet", "DataSystems", "CloudFirst"]),
        "invoice_id": f"INV-{random.randint(10000, 99999)}",
        "amount": f"{random.randint(500, 50000):,.2f}",
        "doc_name": random.choice([
            "Q4 Financial Report", "Project Proposal", "Contract Amendment",
            "Policy Update", "Budget Review", "Vendor Agreement",
        ]),
        "domain": random.choice(["secure-login.example.com", "account.verify.example.com", "portal.internal.test"]),
    }
    return data


def _build_url(base_url, obfuscation_method=None):
    if obfuscation_method and obfuscation_method in URL_OBFUSCATION_TECHNIQUES:
        return URL_OBFUSCATION_TECHNIQUES[obfuscation_method](base_url)
    return base_url


def generate_email(template_name, target_name=None, obfuscation=None, custom_vars=None):
    if template_name not in EMAIL_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}. Available: {list(EMAIL_TEMPLATES.keys())}")

    template = EMAIL_TEMPLATES[template_name]
    data = _generate_placeholder_data(template_name)
    if custom_vars:
        data.update(custom_vars)
    if target_name:
        data["name"] = target_name

    base_url = f"https://{data['domain']}/verify"
    data["link"] = _build_url(base_url, obfuscation)

    subject = template["subject"].format(**data)
    body = template["body"].format(**data)

    return {
        "subject": subject,
        "body": body,
        "from": f"security@{data['domain']}",
        "to": data["name"],
        "template": template_name,
        "obfuscation": obfuscation,
        "timestamp": datetime.now().isoformat(),
    }


def send_email(email_data, smtp_config=None):
    if smtp_config is None:
        smtp_config = {}

    smtp_host = smtp_config.get("host", "127.0.0.1")
    smtp_port = smtp_config.get("port", 25)
    smtp_user = smtp_config.get("username", "")
    smtp_pass = smtp_config.get("password", "")
    use_tls = smtp_config.get("use_tls", False)

    msg = MIMEMultipart()
    msg["From"] = email_data["from"]
    msg["To"] = email_data["to"]
    msg["Subject"] = email_data["subject"]
    msg.attach(MIMEText(email_data["body"], "plain"))

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls(context=context)
                if smtp_user:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(email_data["from"], email_data["to"], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_user:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(email_data["from"], email_data["to"], msg.as_string())

        logger.info("Email sent to %s with subject: %s", email_data["to"], email_data["subject"])
        return {"status": "sent", "to": email_data["to"]}
    except Exception as e:
        logger.error("Failed to send email: %s", e)
        raise


def add_attachment(email_data, file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Attachment not found: {file_path}")

    part = MIMEBase("application", "octet-stream")
    with open(file_path, "rb") as f:
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f'attachment; filename="{os.path.basename(file_path)}"',
    )
    email_data.setdefault("_attachments", []).append(part)
    logger.info("Attachment added: %s", file_path)
    return email_data


def generate_campaign(template_name, targets, count=1, obfuscation=None):
    emails = []
    for i in range(count):
        for target in targets:
            email = generate_email(template_name, target_name=target, obfuscation=obfuscation)
            emails.append(email)
    logger.info("Generated %d phishing emails using template '%s'", len(emails), template_name)
    return emails


def run(config=None):
    if config is None:
        config = {}

    template = config.get("template", "phishing_credential")
    targets = config.get("targets", ["user@example.com"])
    count = config.get("count", 1)
    obfuscation = config.get("obfuscation", None)
    smtp_config = config.get("smtp", {})

    logger.info("Email Campaign Module starting...")
    logger.info("Template: %s", template)
    logger.info("Targets: %d", len(targets))

    emails = generate_campaign(template, targets, count, obfuscation)

    if smtp_config.get("host"):
        for email in emails:
            try:
                send_email(email, smtp_config)
            except Exception as e:
                logger.error("Failed to send email to %s: %s", email["to"], e)

    return emails


if __name__ == "__main__":
    run()
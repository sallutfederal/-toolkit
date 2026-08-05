import json
import random
import string
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("social_engineering")


CHANNEL_TEMPLATES = {
    "sms": {
        "max_length": 160,
        "templates": [
            "URGENT: Your account has been compromised. Verify immediately at {link}",
            "Alert: Unusual login detected on your account. Click {link} to secure it.",
            "Your package delivery failed. Update tracking at {link}",
            "Bank alert: Suspicious transaction of ${amount}. Verify at {link}",
            "IT Security: Your password expires today. Reset at {link}",
        ],
    },
    "whatsapp": {
        "max_length": 4096,
        "templates": [
            "Hey {name}, I found this photo from last week's event. Check it out: {link}",
            "Quick question - can you review this document? {link}",
            "Hey, I'm having trouble with my account. Can you help me verify here? {link}",
            "Someone mentioned you in a group chat. Join here: {link}",
            "Security update required for your account. Click to verify: {link}",
        ],
    },
    "email": {
        "max_length": 50000,
        "templates": [
            "Subject: Action Required - Account Verification\n\nDear {name},\n\nWe detected unusual activity on your account. Please verify your identity: {link}\n\nRegards,\nSecurity Team",
            "Subject: Invoice #{invoice_id}\n\nDear {name},\n\nPlease review and pay the attached invoice. View here: {link}\n\nBest regards,\nFinance",
            "Subject: Document Review - {doc_name}\n\nHi {name},\n\nA document has been shared for your review: {link}\n\nThis is an automated notification.",
        ],
    },
}

AB_TEST_VARIABLES = {
    "urgency": ["immediately", "within 24 hours", "as soon as possible", "urgent"],
    "authority": ["Security Team", "IT Department", "System Administrator", "Compliance Team"],
    "fear": ["account suspension", "data breach", "unauthorized access", "account lockout"],
    "reward": ["exclusive offer", "bonus reward", "special access", "priority support"],
    "curiosity": ["you won't believe this", "check this out", "see what happened", "you need to see this"],
}


def _generate_variant(template, variables):
    text = template
    for key, value in variables.items():
        placeholder = "{" + key + "}"
        if placeholder in text:
            text = text.replace(placeholder, str(value))
    return text


def generate_message(channel, template_index=None, variables=None):
    if channel not in CHANNEL_TEMPLATES:
        raise ValueError(f"Unsupported channel: {channel}. Available: {list(CHANNEL_TEMPLATES.keys())}")

    channel_config = CHANNEL_TEMPLATES[channel]
    templates = channel_config["templates"]

    if template_index is None:
        template_index = random.randint(0, len(templates) - 1)

    template = templates[template_index]

    default_vars = {
        "name": random.choice([
            "John", "Maria", "David", "Sarah", "Robert", "Lisa", "Michael", "Emma",
        ]),
        "link": f"https://{random.choice(['secure', 'verify', 'login', 'account'])}.{random.choice(['example.com', 'test.local'])}",
        "amount": str(random.randint(100, 10000)),
        "invoice_id": f"INV-{random.randint(10000, 99999)}",
        "doc_name": random.choice(["Report", "Document", "Contract", "Invoice"]),
    }
    if variables:
        default_vars.update(variables)

    message = _generate_variant(template, default_vars)

    return {
        "channel": channel,
        "template_index": template_index,
        "message": message,
        "length": len(message),
        "variables_used": default_vars,
        "timestamp": datetime.now().isoformat(),
    }


def generate_ab_test_variants(channel, base_template_index, num_variants=10):
    if channel not in CHANNEL_TEMPLATES:
        raise ValueError(f"Unsupported channel: {channel}")

    channel_config = CHANNEL_TEMPLATES[channel]
    base_template = channel_config["templates"][base_template_index]

    variants = []
    for i in range(num_variants):
        variables = {}
        for var_name, options in A_B_TEST_VARIABLES.items():
            variables[var_name] = random.choice(options)

        message = _generate_variant(base_template, variables)
        variants.append({
            "variant_id": f"v{i+1}",
            "variables": variables,
            "message": message,
            "length": len(message),
        })

    logger.info("Generated %d A/B test variants for channel '%s'", num_variants, channel)
    return variants


def generate_campaign(channel, targets, template_index=None, num_variants=1):
    messages = []
    for target in targets:
        for _ in range(num_variants):
            msg = generate_message(channel, template_index)
            msg["target"] = target
            messages.append(msg)
    logger.info("Generated %d messages for %d targets on channel '%s'", len(messages), len(targets), channel)
    return messages


def generate_multi_channel_campaign(targets, channels=None, template_index=None):
    if channels is None:
        channels = ["sms", "whatsapp", "email"]

    campaign = {}
    for channel in channels:
        campaign[channel] = generate_campaign(channel, targets, template_index)

    total = sum(len(msgs) for msgs in campaign.values())
    logger.info("Multi-channel campaign generated: %d total messages across %d channels", total, len(channels))
    return campaign


def analyze_campaign_effectiveness(campaign_results):
    analysis = {
        "total_messages": 0,
        "by_channel": {},
        "by_urgency": {},
        "avg_length": 0,
        "total_length": 0,
    }

    for channel, messages in campaign_results.items():
        channel_count = len(messages)
        analysis["by_channel"][channel] = channel_count
        analysis["total_messages"] += channel_count

        for msg in messages:
            analysis["total_length"] += msg.get("length", 0)
            urgency = "high" if any(w in msg.get("message", "").lower() for w in ["urgent", "immediately", "as soon"]) else "normal"
            analysis["by_urgency"][urgency] = analysis["by_urgency"].get(urgency, 0) + 1

    if analysis["total_messages"] > 0:
        analysis["avg_length"] = analysis["total_length"] / analysis["total_messages"]

    return analysis


def export_campaign(campaign, output_file, format="json"):
    if format == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(campaign, f, indent=2, default=str)
    elif format == "csv":
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["channel", "target", "message", "length", "timestamp"])
            for channel, messages in campaign.items():
                for msg in messages:
                    writer.writerow([
                        channel,
                        msg.get("target", ""),
                        msg.get("message", "")[:200],
                        msg.get("length", 0),
                        msg.get("timestamp", ""),
                    ])
    logger.info("Campaign exported to %s (%s)", output_file, format)


def run(config=None):
    if config is None:
        config = {}

    mode = config.get("mode", "generate")
    channel = config.get("channel", "email")
    targets = config.get("targets", ["user@example.com"])
    template_index = config.get("template_index", None)
    num_variants = config.get("num_variants", 5)
    output_file = config.get("output_file", None)

    logger.info("Social Engineering Toolkit starting...")
    logger.info("Mode: %s | Channel: %s", mode, channel)

    if mode == "generate":
        messages = generate_campaign(channel, targets, template_index, num_variants)
    elif mode == "ab_test":
        messages = generate_ab_test_variants(channel, template_index or 0, num_variants)
    elif mode == "multi_channel":
        channels = config.get("channels", ["sms", "whatsapp", "email"])
        messages = generate_multi_channel_campaign(targets, channels, template_index)
    elif mode == "analyze":
        campaign = config.get("campaign", {})
        messages = analyze_campaign_effectiveness(campaign)
    else:
        raise ValueError(f"Unknown mode: {mode}")

    if output_file:
        if isinstance(messages, dict):
            export_campaign(messages, output_file)
        else:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(messages, f, indent=2, default=str)
        logger.info("Campaign exported to %s", output_file)

    return messages


if __name__ == "__main__":
    run()
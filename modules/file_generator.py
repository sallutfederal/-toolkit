import csv
import json
import os
import random
import string
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from utils.logger import get_module_logger

logger = get_module_logger("file_generator")


SUPPORTED_FORMATS = ("csv", "json", "xml", "txt", "pdf")

PII_PATTERNS = {
    "credit_card": {
        "prefixes": ["4", "5", "37", "6011", "30", "36", "38", "35"],
        "length": 16,
        "label": "Credit Card Number",
    },
    "ssn": {
        "format": "XXX-XX-XXXX",
        "label": "Social Security Number",
    },
    "email": {
        "domains": ["example.com", "testcorp.com", "internal.local", "mail.test"],
        "label": "Email Address",
    },
    "phone": {
        "formats": ["+1-XXX-XXX-XXXX", "XXX-XXX-XXXX", "(XXX) XXX-XXXX"],
        "label": "Phone Number",
    },
    "ip_address": {
        "subnets": ["10.0.0", "192.168.1", "172.16.0", "10.10.10"],
        "label": "IP Address",
    },
    "name": {
        "first_names": [
            "James", "Mary", "Robert", "Patricia", "John", "Jennifer",
            "Michael", "Linda", "David", "Elizabeth", "William", "Barbara",
            "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah",
            "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
        ],
        "last_names": [
            "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
            "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
            "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore",
            "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
        ],
        "label": "Full Name",
    },
    "address": {
        "streets": [
            "Main St", "Oak Ave", "Elm St", "Park Blvd", "Washington Ave",
            "Lake Dr", "Hill Rd", "Maple Ln", "Cedar Ct", "River Way",
        ],
        "cities": [
            "Springfield", "Riverside", "Greenville", "Fairview", "Madison",
            "Georgetown", "Salem", "Clinton", "Greenwood", "Franklin",
        ],
        "states": ["IL", "CA", "TX", "NY", "FL", "OH", "PA", "MI", "GA", "WA"],
        "label": "Street Address",
    },
    "date_of_birth": {
        "start_year": 1950,
        "end_year": 2005,
        "label": "Date of Birth",
    },
}


def _luhn_checksum(card_number):
    digits = [int(d) for d in str(card_number)]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(divmod(d * 2, 10))
    return checksum % 10


def generate_credit_card(prefix=None):
    if prefix is None:
        prefix = random.choice(PII_PATTERNS["credit_card"]["prefixes"])
    length = PII_PATTERNS["credit_card"]["length"]
    prefix_str = str(prefix)
    remaining = length - len(prefix_str) - 1
    partial = prefix_str + "".join([str(random.randint(0, 9)) for _ in range(remaining)])
    for check_digit in range(10):
        candidate = partial + str(check_digit)
        if _luhn_checksum(candidate) == 0:
            return candidate
    return partial + "0"


def generate_ssn():
    area = random.randint(1, 899)
    group = random.randint(1, 99)
    serial = random.randint(1, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"


def generate_email():
    username = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
    domain = random.choice(PII_PATTERNS["email"]["domains"])
    return f"{username}@{domain}"


def generate_phone():
    fmt = random.choice(PII_PATTERNS["phone"]["formats"])
    result = fmt
    for placeholder in set(c for c in fmt if c == "X"):
        result = result.replace("X", str(random.randint(0, 9)), 1)
    for i in range(10):
        result = result.replace("X", str(random.randint(0, 9)), 1)
    return result


def generate_ip_address():
    subnet = random.choice(PII_PATTERNS["ip_address"]["subnets"])
    return f"{subnet}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_name():
    first = random.choice(PII_PATTERNS["name"]["first_names"])
    last = random.choice(PII_PATTERNS["name"]["last_names"])
    return f"{first} {last}"


def generate_address():
    street_num = random.randint(1, 9999)
    street = random.choice(PII_PATTERNS["address"]["streets"])
    city = random.choice(PII_PATTERNS["address"]["cities"])
    state = random.choice(PII_PATTERNS["address"]["states"])
    zip_code = random.randint(10000, 99999)
    return f"{street_num} {street}, {city}, {state} {zip_code}"


def generate_dob():
    start = datetime(PII_PATTERNS["date_of_birth"]["start_year"], 1, 1)
    end = datetime(PII_PATTERNS["date_of_birth"]["end_year"], 12, 31)
    delta = end - start
    random_days = random.randint(0, delta.days)
    dob = start + timedelta(days=random_days)
    return dob.strftime("%Y-%m-%d")


GENERATORS = {
    "credit_card": generate_credit_card,
    "ssn": generate_ssn,
    "email": generate_email,
    "phone": generate_phone,
    "ip_address": generate_ip_address,
    "name": generate_name,
    "address": generate_address,
    "date_of_birth": generate_dob,
}


def generate_record(patterns):
    record = {}
    for pattern_name in patterns:
        if pattern_name in GENERATORS:
            record[pattern_name] = GENERATORS[pattern_name]()
    return record


def generate_csv(records, output_path, fieldnames=None):
    if not records:
        logger.warning("No records to write to CSV")
        return

    if fieldnames is None:
        fieldnames = list(records[0].keys())

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(record)

    logger.info("CSV file generated: %s (%d records)", output_path, len(records))


def generate_json(records, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)

    logger.info("JSON file generated: %s (%d records)", output_path, len(records))


def generate_xml(records, output_path):
    import xml.etree.ElementTree as ET

    root = ET.Element("records")
    for record in records:
        entry = ET.SubElement(root, "record")
        for key, value in record.items():
            field = ET.SubElement(entry, key)
            field.text = str(value)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)

    logger.info("XML file generated: %s (%d records)", output_path, len(records))


def generate_txt(records, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        for i, record in enumerate(records, 1):
            f.write(f"--- Record {i} ---\n")
            for key, value in record.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")

    logger.info("TXT file generated: %s (%d records)", output_path, len(records))


def generate_pdf(records, output_path):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except ImportError:
        logger.error("reportlab is required for PDF generation. Install with: pip install reportlab")
        raise

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Generated Test Data Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Paragraph(f"Total Records: {len(records)}", styles["Normal"]))
    elements.append(Paragraph("", styles["Normal"]))

    if records:
        fieldnames = list(records[0].keys())
        data = [fieldnames]
        for record in records:
            row = [str(record.get(fn, "")) for fn in fieldnames]
            data.append(row)

        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        elements.append(table)

    doc.build(elements)
    logger.info("PDF file generated: %s (%d records)", output_path, len(records))


FORMAT_GENERATORS = {
    "csv": generate_csv,
    "json": generate_json,
    "xml": generate_xml,
    "txt": generate_txt,
    "pdf": generate_pdf,
}


def generate_files(patterns, record_count=100, output_dir=None, formats=None):
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")

    os.makedirs(output_dir, exist_ok=True)

    if formats is None:
        formats = ["csv", "json"]

    for fmt in formats:
        if fmt not in SUPPORTED_FORMATS:
            logger.warning("Unsupported format '%s', skipping", fmt)
            continue

        records = [generate_record(patterns) for _ in range(record_count)]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"testdata_{timestamp}.{fmt}"
        output_path = os.path.join(output_dir, filename)

        FORMAT_GENERATORS[fmt](records, output_path)

    return output_dir


def run(config=None):
    if config is None:
        config = {}

    patterns = config.get("patterns", ["credit_card", "ssn", "email"])
    record_count = config.get("record_count", 100)
    output_dir = config.get("output_dir", None)
    formats = config.get("formats", ["csv", "json"])

    logger.info("File Generator Module starting...")
    logger.info("Patterns: %s", patterns)
    logger.info("Record count: %d", record_count)
    logger.info("Formats: %s", formats)

    output_path = generate_files(patterns, record_count, output_dir, formats)

    logger.info("File generation complete. Output directory: %s", output_path)
    return output_path


if __name__ == "__main__":
    run()
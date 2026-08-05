import base64
import gzip
import os
import zlib
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("data_exfiltration")


ENCODING_METHODS = {
    "base64": lambda data: base64.b64encode(data).decode("utf-8"),
    "base64_urlsafe": lambda data: base64.urlsafe_b64encode(data).decode("utf-8"),
    "base32": lambda data: base64.b32encode(data).decode("utf-8"),
    "hex": lambda data: data.hex(),
    "rot13": lambda data: _rot13(data.decode("utf-8", errors="ignore")),
    "xor_simple": lambda data: _xor_simple(data, 0x42),
}

PROTOCOL_CHANNELS = {
    "dns": {
        "description": "DNS tunneling via encoded subdomains",
        "max_chunk_size": 63,
    },
    "http": {
        "description": "HTTP POST/GET with encoded payload",
        "max_chunk_size": 4096,
    },
    "icmp": {
        "description": "ICMP echo request tunneling",
        "max_chunk_size": 32,
    },
}


def _rot13(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)


def _xor_simple(data, key):
    key = key & 0xFF
    return bytes(b ^ key for b in data)


def compress_data(data, method="gzip"):
    if isinstance(data, str):
        data = data.encode("utf-8")

    if method == "gzip":
        compressed = gzip.compress(data)
    elif method == "zlib":
        compressed = zlib.compress(data)
    elif method == "none":
        compressed = data
    else:
        raise ValueError(f"Unsupported compression method: {method}")

    ratio = (1 - len(compressed) / len(data)) * 100 if len(data) > 0 else 0

    logger.info("Compressed %d bytes -> %d bytes (%.1f%% reduction)", len(data), len(compressed), ratio)
    return compressed


def encode_data(data, method="base64"):
    if isinstance(data, str):
        data = data.encode("utf-8")

    if method not in ENCODING_METHODS:
        raise ValueError(f"Unsupported encoding method: {method}. Available: {list(ENCODING_METHODS.keys())}")

    encoded = ENCODING_METHODS[method](data)
    if isinstance(encoded, bytes):
        encoded = encoded.decode("utf-8")

    logger.info("Data encoded using %s: %d bytes -> %d chars", method, len(data), len(encoded))
    return encoded


def chunk_data(data, chunk_size=63, channel="dns"):
    if isinstance(data, str):
        data = data.encode("utf-8")

    max_size = PROTOCOL_CHANNELS.get(channel, {}).get("max_chunk_size", chunk_size)
    chunks = []
    for i in range(0, len(data), max_size):
        chunks.append(data[i:i + max_size])

    logger.info("Data split into %d chunks of max %d bytes each", len(chunks), max_size)
    return chunks


def dns_encode(data):
    chunks = chunk_data(data, channel="dns")
    encoded_chunks = []
    for chunk in chunks:
        b64 = base64.b32encode(chunk).decode("utf-8").rstrip("=").lower()
        encoded_chunks.append(b64)
    return encoded_chunks


def http_encode(data, method="POST"):
    encoded = encode_data(data, "base64")
    return {
        "method": method,
        "headers": {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(encoded)),
            "X-Encoding": "base64",
        },
        "body": encoded,
    }


def icmp_encode(data):
    chunks = chunk_data(data, channel="icmp")
    return [chunk.hex() for chunk in chunks]


def exfiltrate(data, channel="http", encoding="base64", compress=True):
    if compress:
        data = compress_data(data, "gzip")

    encoded = encode_data(data, encoding)

    if channel == "dns":
        payload = dns_encode(encoded)
        protocol_info = "DNS tunneling"
    elif channel == "http":
        payload = http_encode(encoded)
        protocol_info = "HTTP POST"
    elif channel == "icmp":
        payload = icmp_encode(encoded)
        protocol_info = "ICMP tunneling"
    else:
        raise ValueError(f"Unsupported channel: {channel}")

    result = {
        "channel": channel,
        "encoding": encoding,
        "compression": compress,
        "protocol_info": protocol_info,
        "original_size": len(data),
        "payload_size": len(str(payload)),
        "chunks": len(payload) if isinstance(payload, list) else 1,
        "timestamp": datetime.now().isoformat(),
    }

    if isinstance(payload, list):
        result["payload_sample"] = payload[:3]
    else:
        result["payload_sample"] = str(payload)[:200]

    logger.info("Data exfiltration package ready via %s", protocol_info)
    return result


def simulate_dns_tunnel(data, domain="example.com"):
    encoded_chunks = dns_encode(data)
    queries = [f"{chunk}.{domain}" for chunk in encoded_chunks]

    logger.info("Simulated %d DNS queries for %s", len(queries), domain)
    return {
        "domain": domain,
        "query_count": len(queries),
        "queries": queries,
    }


def simulate_http_exfil(data, endpoint="/api/collect", host="10.0.0.1"):
    encoded = http_encode(data)
    url = f"http://{host}{endpoint}"

    logger.info("Simulated HTTP exfiltration to %s", url)
    return {
        "url": url,
        "method": encoded["method"],
        "headers": encoded["headers"],
        "body_preview": encoded["body"][:100],
    }


def simulate_icmp_tunnel(data, target="10.0.0.1"):
    chunks = icmp_encode(data)

    logger.info("Simulated %d ICMP tunnels to %s", len(chunks), target)
    return {
        "target": target,
        "packet_count": len(chunks),
        "payloads": chunks[:5],
    }


def run(config=None):
    if config is None:
        config = {}

    data = config.get("data", "test data for exfiltration")
    channel = config.get("channel", "http")
    encoding = config.get("encoding", "base64")
    compress = config.get("compress", True)
    output_file = config.get("output_file", None)

    logger.info("Data Exfiltration Module starting...")
    logger.info("Channel: %s | Encoding: %s | Compress: %s", channel, encoding, compress)

    result = exfiltrate(data, channel, encoding, compress)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info("Exfiltration report saved to %s", output_file)

    return result


if __name__ == "__main__":
    run()
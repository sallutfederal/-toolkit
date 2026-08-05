import socket
import concurrent.futures
import ipaddress
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("lateral_movement")


DEFAULT_SCAN_PORTS = [
    135, 139, 445, 3389, 5985, 5986, 22, 23, 443, 80,
    8080, 8443, 1433, 3306, 5432, 6379, 27017, 9200, 9443,
]

TRUST_RELATIONSHIP_PORTS = {
    445: "SMB",
    135: "MSRPC",
    139: "NetBIOS",
    3389: "RDP",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    22: "SSH",
    23: "Telnet",
}

COMMON_CREDENTIAL_PATTERNS = [
    r"admin", r"administrator", r"root", r"user", r"test",
    r"guest", r"service", r"backup", r"support", r"manager",
]


def _check_port(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.timeout, OSError):
        return False


def _detect_service(host, port, timeout=3):
    if port in TRUST_RELATIONSHIP_PORTS:
        return TRUST_RELATIONSHIP_PORTS[port]

    banner = _grab_banner(host, port, timeout)
    if banner:
        return banner[:64]
    return f"Port-{port}"


def _grab_banner(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 443, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        sock.close()
        if banner:
            return banner.decode("utf-8", errors="ignore").strip().split("\r\n")[0]
        return None
    except Exception:
        return None


def _fingerprint_os(host, timeout=5):
    os_guesses = []
    for port in [22, 445, 3389]:
        if _check_port(host, port, timeout):
            banner = _grab_banner(host, port, timeout)
            if banner:
                banner_lower = banner.lower()
                if any(kw in banner_lower for kw in ["ssh", "linux", "ubuntu", "debian", "centos", "red hat"]):
                    os_guesses.append("Linux")
                elif any(kw in banner_lower for kw in ["microsoft", "windows", "iis"]):
                    os_guesses.append("Windows")
                elif any(kw in banner_lower for kw in ["openbsd", "freebsd", "netbsd"]):
                    os_guesses.append("BSD")
    if not os_guesses:
        os_guesses.append("Unknown")
    return os_guesses[0]


def _check_trust_relationship(source_host, target_host, ports=None, timeout=3):
    if ports is None:
        ports = [445, 3389, 5985, 5986, 22]

    trust_indicators = []

    for port in ports:
        if _check_port(target_host, port, timeout):
            service = TRUST_RELATIONSHIP_PORTS.get(port, f"Port-{port}")
            trust_indicators.append({
                "port": port,
                "service": service,
                "state": "open",
                "trust_type": _classify_trust_type(port),
            })

    return {
        "source": source_host,
        "target": target_host,
        "trust_indicators": trust_indicators,
        "trust_score": len(trust_indicators),
        "has_trust": len(trust_indicators) > 0,
    }


def _classify_trust_type(port):
    trust_map = {
        445: "file_share",
        135: "rpc",
        139: "netbios",
        3389: "remote_desktop",
        5985: "winrm",
        5986: "winrm_ssl",
        22: "ssh",
        23: "telnet",
    }
    return trust_map.get(port, "unknown")


def map_host_trusts(host, targets, ports=None, timeout=3, max_threads=50):
    if ports is None:
        ports = DEFAULT_SCAN_PORTS

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_check_trust_relationship, host, target, ports, timeout): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                result = future.result()
                if result["has_trust"]:
                    results.append(result)
                    logger.info("Trust relationship found: %s -> %s (%d indicators)", host, target, result["trust_score"])
            except Exception as e:
                logger.error("Error checking trust to %s: %s", target, e)

    return sorted(results, key=lambda r: r["trust_score"], reverse=True)


def map_network_trusts(targets, ports=None, timeout=3, max_threads=50):
    all_trusts = {}
    targets_list = list(targets)

    for source in targets_list:
        other_targets = [t for t in targets_list if t != source]
        trusts = map_host_trusts(source, other_targets, ports, timeout, max_threads)
        if trusts:
            all_trusts[source] = trusts

    return all_trusts


def build_trust_graph(trust_map):
    graph = {}
    for source, trusts in trust_map.items():
        if source not in graph:
            graph[source] = {"outbound": [], "inbound": [], "os": "Unknown"}
        for trust in trusts:
            target = trust["target"]
            graph[source]["outbound"].append({
                "target": target,
                "port": trust["trust_indicators"][0]["port"] if trust["trust_indicators"] else None,
                "service": trust["trust_indicators"][0]["service"] if trust["trust_indicators"] else None,
                "trust_type": trust["trust_indicators"][0]["trust_type"] if trust["trust_indicators"] else None,
            })
            if target not in graph:
                graph[target] = {"outbound": [], "inbound": [], "os": "Unknown"}
            graph[target]["inbound"].append({
                "source": source,
                "port": trust["trust_indicators"][0]["port"] if trust["trust_indicators"] else None,
                "service": trust["trust_indicators"][0]["service"] if trust["trust_indicators"] else None,
            })
    return graph


def identify_high_value_targets(trust_map, min_trust_score=3):
    high_value = []
    for source, trusts in trust_map.items():
        for trust in trusts:
            if trust["trust_score"] >= min_trust_score:
                high_value.append({
                    "host": source,
                    "target": trust["target"],
                    "trust_score": trust["trust_score"],
                    "indicators": trust["trust_indicators"],
                })
    return sorted(high_value, key=lambda x: x["trust_score"], reverse=True)


def generate_lateral_movement_report(trust_map, output_file=None):
    lines = []
    lines.append("=" * 70)
    lines.append("LATERAL MOVEMENT TRUST MAP REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total source hosts: {len(trust_map)}")
    lines.append("=" * 70)

    total_relationships = sum(len(trusts) for trusts in trust_map.values())
    lines.append(f"Total trust relationships: {total_relationships}")
    lines.append("")

    for source, trusts in sorted(trust_map.items()):
        lines.append(f"Source: {source}")
        lines.append("-" * 40)
        for trust in trusts:
            lines.append(f"  -> {trust['target']} (Score: {trust['trust_score']})")
            for indicator in trust["trust_indicators"]:
                lines.append(f"     Port {indicator['port']}: {indicator['service']} [{indicator['trust_type']}]")
        lines.append("")

    report = "\n".join(lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Lateral movement report saved to %s", output_file)

    return report


def run(config=None):
    if config is None:
        config = {}

    targets = config.get("targets", ["127.0.0.1"])
    ports = config.get("ports", DEFAULT_SCAN_PORTS)
    timeout = config.get("timeout", 3)
    max_threads = config.get("max_threads", 50)
    output_file = config.get("output_file", None)
    min_trust_score = config.get("min_trust_score", 3)

    logger.info("Lateral Movement Module starting...")
    logger.info("Targets: %d hosts", len(targets))

    trust_map = map_network_trusts(targets, ports, timeout, max_threads)
    report = generate_lateral_movement_report(trust_map, output_file)

    high_value = identify_high_value_targets(trust_map, min_trust_score)
    logger.info("Lateral movement mapping complete. %d trust relationships found.", sum(len(v) for v in trust_map.values()))
    logger.info("High-value targets (score >= %d): %d", min_trust_score, len(high_value))

    return {
        "trust_map": trust_map,
        "high_value_targets": high_value,
        "trust_graph": build_trust_graph(trust_map),
    }


if __name__ == "__main__":
    run()
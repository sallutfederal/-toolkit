import socket
import concurrent.futures
import ipaddress
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("network_discovery")


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200, 9443,
]

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    9200: "Elasticsearch",
    9443: "HTTPS-Alt2",
}


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        logger.error("DNS resolution failed for %s: %s", host, e)
        return None


def scan_port(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = grab_banner(host, port, timeout)
            sock.close()
            return {"host": host, "port": port, "state": "open", "service": service}
        sock.close()
        return None
    except socket.timeout:
        logger.debug("Timeout scanning %s:%d", host, port)
        return None
    except OSError as e:
        logger.debug("OS error scanning %s:%d: %s", host, port, e)
        return None


def grab_banner(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 443, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        sock.close()
        if banner:
            decoded = banner.decode("utf-8", errors="ignore").strip()
            first_line = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded
            return first_line[:128]
        return COMMON_SERVICES.get(port, "unknown")
    except Exception:
        return COMMON_SERVICES.get(port, "unknown")


def scan_host(host, ports=None, timeout=3, max_threads=100):
    if ports is None:
        ports = DEFAULT_PORTS

    resolved = resolve_host(host)
    if resolved is None:
        logger.warning("Could not resolve host: %s", host)
        return []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, resolved, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                logger.info(
                    "Open port found: %s:%d (%s)", result["host"], result["port"], result["service"]
                )

    return sorted(results, key=lambda r: r["port"])


def scan_range(cidr, ports=None, timeout=3, max_threads=100):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        logger.error("Invalid CIDR range %s: %s", cidr, e)
        return {}

    all_results = {}
    hosts = list(network.hosts())
    logger.info("Scanning %d hosts in %s", len(hosts), cidr)

    for host in hosts:
        host_str = str(host)
        results = scan_host(host_str, ports, timeout, max_threads)
        if results:
            all_results[host_str] = results

    return all_results


def discover_network(targets, ports=None, timeout=3, max_threads=100):
    results = {}
    for target in targets:
        logger.info("Starting scan for target: %s", target)
        if "/" in target:
            results.update(scan_range(target, ports, timeout, max_threads))
        else:
            host_results = scan_host(target, ports, timeout, max_threads)
            if host_results:
                results[target] = host_results
    return results


def generate_report(results, output_file=None):
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("NETWORK DISCOVERY REPORT")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 70)

    total_hosts = len(results)
    total_open_ports = sum(len(ports) for ports in results.values())
    report_lines.append(f"Total hosts discovered: {total_hosts}")
    report_lines.append(f"Total open ports found: {total_open_ports}")
    report_lines.append("")

    for host, ports in sorted(results.items()):
        report_lines.append(f"Host: {host}")
        report_lines.append("-" * 40)
        for svc in ports:
            report_lines.append(
                f"  Port {svc['port']:>5}/tcp  OPEN  {svc['service']}"
            )
        report_lines.append("")

    report = "\n".join(report_lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Report saved to %s", output_file)

    return report


def run(config=None):
    if config is None:
        config = {}

    targets = config.get("targets", ["127.0.0.1"])
    ports = config.get("ports", DEFAULT_PORTS)
    timeout = config.get("timeout", 3)
    max_threads = config.get("max_threads", 100)
    output_file = config.get("output_file", None)

    logger.info("Network Discovery Module starting...")
    logger.info("Targets: %s", targets)
    logger.info("Ports: %s", ports)

    results = discover_network(targets, ports, timeout, max_threads)
    report = generate_report(results, output_file)

    logger.info("Network discovery complete. %d hosts found.", len(results))
    return results


if __name__ == "__main__":
    run()
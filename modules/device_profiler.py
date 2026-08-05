import socket
import re
import concurrent.futures
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("device_profiler")


DEFAULT_SSH_BANNERS = {
    "OpenSSH": "SSH",
    "dropbear": "SSH",
    "libssh": "SSH",
    "SSH-2.0": "SSH",
}

DEFAULT_HTTP_BANNERS = {
    "Apache": "Web Server",
    "nginx": "Web Server",
    "Microsoft-IIS": "Web Server",
    "lighttpd": "Web Server",
    "Jetty": "Web Server",
    "Cowboy": "Web Server",
}

DEFAULT_SNMP_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
}

DEVICE_FINGERPRINTS = {
    "cisco_ios": {
        "keywords": ["Cisco IOS", "IOS"],
        "device_type": "Network Router/Switch",
        "vendor": "Cisco",
    },
    "cisco_nxos": {
        "keywords": ["NX-OS"],
        "device_type": "Network Switch",
        "vendor": "Cisco",
    },
    "juniper_junos": {
        "keywords": ["JUNOS"],
        "device_type": "Network Router",
        "vendor": "Juniper",
    },
    "arista_eos": {
        "keywords": ["Arista", "EOS"],
        "device_type": "Network Switch",
        "vendor": "Arista",
    },
    "hp_procurve": {
        "keywords": ["ProCurve", "HPE"],
        "device_type": "Network Switch",
        "vendor": "HPE",
    },
    "fortinet_fortios": {
        "keywords": ["FortiGate", "FortiOS"],
        "device_type": "Firewall",
        "vendor": "Fortinet",
    },
    "paloalto_panos": {
        "keywords": ["PAN-OS"],
        "device_type": "Firewall",
        "vendor": "Palo Alto Networks",
    },
    "checkpoint_gaia": {
        "keywords": ["Check Point", "Gaia"],
        "device_type": "Firewall",
        "vendor": "Check Point",
    },
    "linux_server": {
        "keywords": ["Linux", "Ubuntu", "Debian", "CentOS", "Red Hat"],
        "device_type": "Server",
        "vendor": "Various",
    },
    "windows_server": {
        "keywords": ["Windows", "Microsoft"],
        "device_type": "Server",
        "vendor": "Microsoft",
    },
    "vmware_esxi": {
        "keywords": ["VMware", "ESXi"],
        "device_type": "Hypervisor",
        "vendor": "VMware",
    },
    "printer": {
        "keywords": ["printer", "Printer", "HP Laser", "Epson"],
        "device_type": "Printer",
        "vendor": "Unknown",
    },
    "ip_camera": {
        "keywords": ["IP Camera", "camera", "ONVIF"],
        "device_type": "IP Camera",
        "vendor": "Unknown",
    },
    "iot_device": {
        "keywords": ["IoT", "embedded", "RTOS"],
        "device_type": "IoT Device",
        "vendor": "Unknown",
    },
}


def _tcp_banner_grab(host, port, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if port == 22:
            sock.send(b"\n")
        elif port in (80, 443, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        elif port == 21:
            pass
        elif port == 25:
            pass

        banner = sock.recv(2048)
        sock.close()
        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def _parse_ssh_banner(banner):
    if not banner:
        return None

    match = re.match(r"SSH-(\d+\.\d+)-(.+)", banner)
    if match:
        version = match.group(1)
        software = match.group(2).split("-")[0] if "-" in match.group(2) else match.group(2)
        return {"protocol_version": version, "software": software, "type": "SSH"}

    return {"raw": banner[:128], "type": "SSH"}


def _parse_http_banner(banner):
    if not banner:
        return None

    server_match = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
    if server_match:
        server = server_match.group(1).strip()
        return {"server": server, "type": "HTTP"}

    return {"raw": banner[:128], "type": "HTTP"}


def _classify_device(banner, service_type):
    if not banner:
        return {"device_type": "Unknown", "vendor": "Unknown"}

    banner_lower = banner.lower()
    for fingerprint_name, fingerprint in DEVICE_FINGERPRINTS.items():
        for keyword in fingerprint["keywords"]:
            if keyword.lower() in banner_lower:
                return {
                    "device_type": fingerprint["device_type"],
                    "vendor": fingerprint["vendor"],
                    "fingerprint": fingerprint_name,
                }

    return {"device_type": "Unknown", "vendor": "Unknown"}


def _snmp_query(host, community, oid, timeout=5):
    try:
        from pysnmp.hlapi import (
            getCmd,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )
    except ImportError:
        logger.warning("pysnmp not available, skipping SNMP queries")
        return None

    try:
        iterator = getCmd(
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            return None
        if error_status:
            return None

        for var_bind in var_binds:
            return str(var_bind[1])
    except Exception:
        return None


def profile_device(host, ports=None, timeout=5):
    if ports is None:
        ports = [21, 22, 23, 80, 443, 161, 3389, 5900, 8080]

    profile = {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "services": [],
        "device_type": "Unknown",
        "vendor": "Unknown",
        "firmware": None,
        "os": None,
    }

    for port in ports:
        banner = _tcp_banner_grab(host, port, timeout)
        if banner is None:
            continue

        service_info = {"port": port, "banner": banner[:256]}

        if port == 22:
            ssh_info = _parse_ssh_banner(banner)
            service_info["parsed"] = ssh_info
            if ssh_info.get("software"):
                profile["os"] = ssh_info["software"]
                profile["firmware"] = ssh_info.get("software")

        elif port in (80, 443, 8080, 8443):
            http_info = _parse_http_banner(banner)
            service_info["parsed"] = http_info
            if http_info.get("server"):
                profile["os"] = http_info.get("server")

        service_info["device_classification"] = _classify_device(banner, "tcp")
        profile["services"].append(service_info)

    if profile["services"]:
        first_service = profile["services"][0]
        classification = first_service.get("device_classification", {})
        profile["device_type"] = classification.get("device_type", "Unknown")
        profile["vendor"] = classification.get("vendor", "Unknown")

    return profile


def profile_network(targets, ports=None, timeout=5, max_threads=50):
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(profile_device, target, ports, timeout): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                profile = future.result()
                results[target] = profile
                logger.info(
                    "Profiled %s: %s (%s)",
                    target,
                    profile["device_type"],
                    profile["vendor"],
                )
            except Exception as e:
                logger.error("Failed to profile %s: %s", target, e)
                results[target] = {"host": target, "error": str(e)}

    return results


def generate_inventory_report(profiles, output_file=None):
    lines = []
    lines.append("=" * 70)
    lines.append("DEVICE INVENTORY REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total devices: {len(profiles)}")
    lines.append("=" * 70)

    for host, profile in sorted(profiles.items()):
        lines.append(f"\nHost: {host}")
        lines.append("-" * 40)
        lines.append(f"  Device Type: {profile.get('device_type', 'Unknown')}")
        lines.append(f"  Vendor: {profile.get('vendor', 'Unknown')}")
        lines.append(f"  OS/Firmware: {profile.get('os') or profile.get('firmware') or 'Unknown'}")

        services = profile.get("services", [])
        if services:
            lines.append(f"  Open Ports ({len(services)}):")
            for svc in services:
                lines.append(f"    Port {svc['port']}: {svc['banner'][:80]}")

    report = "\n".join(lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Inventory report saved to %s", output_file)

    return report


def run(config=None):
    if config is None:
        config = {}

    targets = config.get("targets", ["127.0.0.1"])
    ports = config.get("ports", None)
    timeout = config.get("timeout", 5)
    max_threads = config.get("max_threads", 50)
    output_file = config.get("output_file", None)

    logger.info("Device Profiler Module starting...")
    logger.info("Targets: %s", targets)

    profiles = profile_network(targets, ports, timeout, max_threads)
    report = generate_inventory_report(profiles, output_file)

    logger.info("Device profiling complete. %d devices profiled.", len(profiles))
    return profiles


if __name__ == "__main__":
    run()
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config import load_config, get_section
from utils.logger import setup_logger

from modules.network_discovery import run as run_network_discovery
from modules.file_generator import run as run_file_generator
from modules.remote_communication import run as run_remote_communication
from modules.vulnerability_bridge import run as run_vulnerability_bridge
from modules.device_profiler import run as run_device_profiler
from modules.transaction_analyzer import run as run_transaction_analyzer


def main():
    parser = argparse.ArgumentParser(
        description="Security Automation Toolkit - Infrastructure Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py network --targets 10.0.0.0/24 --ports 22,80,443
  python main.py files --patterns credit_card,ssn,email --count 500
  python main.py telegram --send "Alert: scan complete" --chat 12345
  python main.py vuln --target 192.168.1.100 --scan
  python main.py profile --targets 10.0.0.1,10.0.0.2
  python main.py txanalyze --input blockchain_data.json
        """,
    )

    parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration file (default: config/settings.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Module to execute")

    # Network Discovery
    net_parser = subparsers.add_parser("network", help="Network port and service scanner")
    net_parser.add_argument("--targets", nargs="+", default=None, help="Target hosts or CIDR ranges")
    net_parser.add_argument("--ports", nargs="+", default=None, help="Ports to scan (comma-separated)")
    net_parser.add_argument("--timeout", type=float, default=3, help="Connection timeout in seconds")
    net_parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads")
    net_parser.add_argument("--output", default=None, help="Output report file path")

    # File Generator
    file_parser = subparsers.add_parser("files", help="Generate structured test files for DLP testing")
    file_parser.add_argument("--patterns", nargs="+", default=None, help="Data patterns to generate")
    file_parser.add_argument("--count", type=int, default=100, help="Number of records per file")
    file_parser.add_argument("--formats", nargs="+", default=None, help="Output formats (csv,json,xml,txt,pdf)")
    file_parser.add_argument("--output-dir", default=None, help="Output directory")

    # Remote Communication
    comm_parser = subparsers.add_parser("telegram", help="Telegram relay for agent communication")
    comm_parser.add_argument("--send", default=None, help="Message to send")
    comm_parser.add_argument("--chat", default=None, help="Telegram chat ID")
    comm_parser.add_argument("--broadcast", default=None, help="Broadcast message to all agents")
    comm_parser.add_argument("--poll", action="store_true", help="Poll for incoming messages")
    comm_parser.add_argument("--status", action="store_true", help="Show agent status")

    # Vulnerability Bridge
    vuln_parser = subparsers.add_parser("vuln", help="Metasploit vulnerability assessment bridge")
    vuln_parser.add_argument("--target", default=None, help="Target host to validate")
    vuln_parser.add_argument("--port", type=int, default=None, help="Target port")
    vuln_parser.add_argument("--scan", action="store_true", help="Run auxiliary scanner")
    vuln_parser.add_argument("--list-modules", action="store_true", help="List available modules")
    vuln_parser.add_argument("--search", default=None, help="Search modules by keyword")

    # Device Profiler
    prof_parser = subparsers.add_parser("profile", help="Device type and firmware profiler")
    prof_parser.add_argument("--targets", nargs="+", default=None, help="Target hosts to profile")
    prof_parser.add_argument("--ports", nargs="+", type=int, default=None, help="Ports to probe")
    prof_parser.add_argument("--timeout", type=float, default=5, help="Probe timeout in seconds")
    prof_parser.add_argument("--output", default=None, help="Output report file path")

    # Transaction Analyzer
    tx_parser = subparsers.add_parser("txanalyze", help="Blockchain transaction analyzer")
    tx_parser.add_argument("--input", required=True, help="Input transaction file (JSON/CSV)")
    tx_parser.add_argument("--address", default=None, help="Address to trace")
    tx_parser.add_argument("--depth", type=int, default=3, help="Trace depth for flow analysis")
    tx_parser.add_argument("--output-dir", default=None, help="Output directory for reports")

    args = parser.parse_args()

    config = load_config(args.config)

    log_level_str = get_section(config, "general", required=False).get("log_level", "INFO")
    log_level = getattr(__import__("logging"), log_level_str.upper(), logging.INFO)
    log_dir = get_section(config, "general", required=False).get("log_dir", "logs")
    os.makedirs(log_dir, exist_ok=True)

    setup_logger(
        "security_toolkit",
        log_file=os.path.join(log_dir, "toolkit.log"),
        level=log_level,
    )

    if args.command is None:
        parser.print_help()
        return

    try:
        if args.command == "network":
            ports = None
            if args.ports:
                ports = []
                for p in args.ports:
                    ports.extend(int(x) for x in p.split(","))
            targets = None
            if args.targets:
                targets = []
                for t in args.targets:
                    targets.extend(t.split(","))
            run_network_discovery({
                "targets": targets or ["127.0.0.1"],
                "ports": ports,
                "timeout": args.timeout,
                "max_threads": args.threads,
                "output_file": args.output,
            })

        elif args.command == "files":
            patterns = None
            if args.patterns:
                patterns = []
                for p in args.patterns:
                    patterns.extend(p.split(","))
            formats = None
            if args.formats:
                formats = []
                for f in args.formats:
                    formats.extend(f.split(","))
            run_file_generator({
                "patterns": patterns or ["credit_card", "ssn", "email"],
                "record_count": args.count,
                "formats": formats or ["csv", "json"],
                "output_dir": args.output_dir,
            })

        elif args.command == "telegram":
            relay = run_remote_communication(config)
            if args.send:
                chat_id = args.chat or config.get("remote_communication", {}).get("telegram", {}).get("chat_id")
                relay.send_to_agent("soc", args.send)
                print(f"Message sent: {args.send}")
            elif args.broadcast:
                results = relay.broadcast(args.broadcast)
                for agent, status in results.items():
                    print(f"  {agent}: {status['status']}")
            elif args.poll:
                print("Starting message poll... (Ctrl+C to stop)")
                relay.poll_messages(0, lambda msg: print(f"Received: {msg}"))
            elif args.status:
                for agent_id in relay._agents:
                    status = relay.get_agent_status(agent_id)
                    print(f"  {agent_id}: {status['status']}")
            else:
                print("Telegram relay initialized. Use --send, --broadcast, --poll, or --status.")

        elif args.command == "vuln":
            bridge = run_vulnerability_bridge(config)
            if args.list_modules:
                modules = bridge.list_modules()
                for mtype, mods in modules.items():
                    print(f"\n{mtype.upper()} ({len(mods)} modules):")
                    for mod in mods[:20]:
                        print(f"  - {mod}")
            elif args.search:
                results = bridge.search_modules(args.search)
                print(f"Found {len(results)} modules matching '{args.search}':")
                for mod in results[:20]:
                    print(f"  - {mod}")
            elif args.target:
                result = bridge.validate_target(args.target, args.port)
                print(f"Validation complete for {args.target}: {result}")
            else:
                print("Metasploit bridge initialized. Use --target, --list-modules, or --search.")

        elif args.command == "profile":
            targets = None
            if args.targets:
                targets = []
                for t in args.targets:
                    targets.extend(t.split(","))
            run_device_profiler({
                "targets": targets or ["127.0.0.1"],
                "ports": args.ports,
                "timeout": args.timeout,
                "output_file": args.output,
            })

        elif args.command == "txanalyze":
            run_transaction_analyzer({
                "input_file": args.input,
                "address": args.address,
                "depth": args.depth,
                "output_dir": args.output_dir,
                "suspicious_threshold": config.get("transaction_analyzer", {}).get("suspicious_threshold", 10000),
            })

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        logger = setup_logger("security_toolkit")
        logger.error("Error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
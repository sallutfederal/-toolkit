import json
import csv
import os
from collections import defaultdict
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("blockchain_forensic")


SUPPORTED_CHAINS = {
    "ethereum": {"chain_id": 1, "explorer": "https://etherscan.io", "native_token": "ETH"},
    "bsc": {"chain_id": 56, "explorer": "https://bscscan.com", "native_token": "BNB"},
    "polygon": {"chain_id": 137, "explorer": "https://polygonscan.com", "native_token": "MATIC"},
    "bitcoin": {"chain_id": 0, "explorer": "https://blockstream.info", "native_token": "BTC"},
    "avalanche": {"chain_id": 43114, "explorer": "https://snowtrace.io", "native_token": "AVAX"},
    "arbitrum": {"chain_id": 42161, "explorer": "https://arbiscan.io", "native_token": "ETH"},
}


class BlockchainForensicAnalyzer:
    def __init__(self, config=None):
        self.config = config or {}
        self.chains = self.config.get("chains", ["ethereum", "bsc", "polygon"])
        self.transactions = []
        self.address_profiles = {}
        self.suspicious_patterns = []
        self.flow_paths = []

    def load_from_json(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            raise
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in %s: %s", file_path, e)
            raise

        if isinstance(data, list):
            self.transactions = data
        elif isinstance(data, dict):
            if "transactions" in data:
                self.transactions = data["transactions"]
            elif "result" in data:
                self.transactions = data["result"]
            else:
                self.transactions = [data]
        else:
            self.transactions = [data]

        logger.info("Loaded %d transactions from %s", len(self.transactions), file_path)
        return len(self.transactions)

    def load_from_csv(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                self.transactions = list(reader)
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            raise

        logger.info("Loaded %d transactions from %s", len(self.transactions), file_path)
        return len(self.transactions)

    def load_from_file(self, file_path):
        if file_path.endswith(".json"):
            return self.load_from_json(file_path)
        elif file_path.endswith(".csv"):
            return self.load_from_csv(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path}")

    def _normalize_tx(self, tx):
        return {
            "hash": tx.get("hash", tx.get("txHash", tx.get("transactionHash", ""))),
            "from": tx.get("from", tx.get("sender", tx.get("inputAddress", ""))),
            "to": tx.get("to", tx.get("receiver", tx.get("outputAddress", ""))),
            "value": self._parse_value(tx.get("value", tx.get("amount", tx.get("valueEth", "0")))),
            "timestamp": tx.get("timestamp", tx.get("blockTimestamp", tx.get("time", ""))),
            "block": tx.get("block", tx.get("blockNumber", tx.get("height", ""))),
            "chain_id": tx.get("chain_id", tx.get("chainId", tx.get("network", "unknown"))),
            "gas": tx.get("gas", tx.get("gasUsed", "")),
            "gas_price": tx.get("gasPrice", tx.get("gasPrice", "")),
            "type": tx.get("type", tx.get("txType", "transfer")),
        }

    def _parse_value(self, value):
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            cleaned = value.replace(",", "").replace(" ", "")
            try:
                return float(cleaned)
            except ValueError:
                return 0.0
        return 0.0

    def _identify_chain(self, tx):
        chain_id = tx.get("chain_id", "unknown")
        for chain_name, chain_info in SUPPORTED_CHAINS.items():
            if str(chain_info["chain_id"]) == str(chain_id):
                return chain_name
        return chain_id if isinstance(chain_id, str) else "unknown"

    def analyze(self):
        self.address_profiles.clear()
        self.suspicious_patterns.clear()
        self.flow_paths.clear()

        chain_stats = defaultdict(lambda: {"count": 0, "volume": 0.0, "addresses": set()})

        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            chain = self._identify_chain(normalized)
            from_addr = normalized["from"]
            to_addr = normalized["to"]
            value = normalized["value"]

            chain_stats[chain]["count"] += 1
            chain_stats[chain]["volume"] += value
            if from_addr:
                chain_stats[chain]["addresses"].add(from_addr)
            if to_addr:
                chain_stats[chain]["addresses"].add(to_addr)

            self._update_address_profile(from_addr, "outgoing", value)
            self._update_address_profile(to_addr, "incoming", value)

        self._detect_cross_chain_activity(chain_stats)
        self._detect_rapid_movements()
        self._detect_mixing_patterns()
        self._detect_high_value_flows()

        return {
            "total_transactions": len(self.transactions),
            "chains_analyzed": len(chain_stats),
            "chain_breakdown": dict(chain_stats),
            "suspicious_patterns": len(self.suspicious_patterns),
        }

    def _update_address_profile(self, address, direction, value):
        if not address:
            return
        if address not in self.address_profiles:
            self.address_profiles[address] = {
                "total_in": 0.0,
                "total_out": 0.0,
                "tx_count": 0,
                "first_seen": None,
                "last_seen": None,
                "chains": set(),
            }
        profile = self.address_profiles[address]
        if direction == "incoming":
            profile["total_in"] += value
        else:
            profile["total_out"] += value
        profile["tx_count"] += 1

    def _detect_cross_chain_activity(self, chain_stats):
        for chain_name, stats in chain_stats.items():
            if stats["count"] > 100:
                self.suspicious_patterns.append({
                    "type": "high_volume_chain",
                    "chain": chain_name,
                    "tx_count": stats["count"],
                    "volume": stats["volume"],
                    "description": f"High volume activity on {chain_name}: {stats['count']} transactions",
                })

    def _detect_rapid_movements(self):
        address_timestamps = defaultdict(list)
        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            from_addr = normalized["from"]
            if from_addr and normalized["timestamp"]:
                address_timestamps[from_addr].append(normalized["timestamp"])

        for addr, timestamps in address_timestamps.items():
            if len(timestamps) > 20:
                self.suspicious_patterns.append({
                    "type": "rapid_movement",
                    "address": addr,
                    "tx_count": len(timestamps),
                    "description": f"Address {addr[:16]}... shows rapid transaction activity",
                })

    def _detect_mixing_patterns(self):
        split_addresses = defaultdict(list)
        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            from_addr = normalized["from"]
            to_addr = normalized["to"]
            value = normalized["value"]
            if from_addr and to_addr and value > 0:
                split_addresses[from_addr].append(to_addr)

        for addr, targets in split_addresses.items():
            unique_targets = set(targets)
            if len(unique_targets) > 10:
                self.suspicious_patterns.append({
                    "type": "mixing_pattern",
                    "address": addr,
                    "output_count": len(unique_targets),
                    "description": f"Address {addr[:16]}... distributes to {len(unique_targets)} unique addresses",
                })

    def _detect_high_value_flows(self):
        threshold = self.config.get("suspicious_threshold", 50000)
        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            value = normalized["value"]
            if value > threshold:
                self.suspicious_patterns.append({
                    "type": "high_value_flow",
                    "hash": normalized["hash"],
                    "from": normalized["from"],
                    "to": normalized["to"],
                    "value": value,
                    "chain": self._identify_chain(normalized),
                    "description": f"High value transfer of {value} on {self._identify_chain(normalized)}",
                })

    def trace_flow(self, address, depth=4):
        flow = []
        visited = set()

        def _trace(addr, current_depth, direction):
            if current_depth > depth or addr in visited or not addr:
                return
            visited.add(addr)

            for tx in self.transactions:
                normalized = self._normalize_tx(tx)
                if normalized["from"] == addr and direction == "outgoing":
                    flow.append({
                        "direction": "outgoing",
                        "hash": normalized["hash"],
                        "to": normalized["to"],
                        "value": normalized["value"],
                        "chain": self._identify_chain(normalized),
                        "timestamp": normalized["timestamp"],
                    })
                    _trace(normalized["to"], current_depth + 1, "outgoing")
                elif normalized["to"] == addr and direction == "incoming":
                    flow.append({
                        "direction": "incoming",
                        "hash": normalized["hash"],
                        "from": normalized["from"],
                        "value": normalized["value"],
                        "chain": self._identify_chain(normalized),
                        "timestamp": normalized["timestamp"],
                    })
                    _trace(normalized["from"], current_depth + 1, "incoming")

        _trace(address, 0, "both")
        return flow

    def get_address_report(self, address):
        incoming = []
        outgoing = []

        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            if normalized["from"] == address:
                outgoing.append(normalized)
            elif normalized["to"] == address:
                incoming.append(normalized)

        profile = self.address_profiles.get(address, {})

        return {
            "address": address,
            "total_received": sum(tx["value"] for tx in incoming),
            "total_sent": sum(tx["value"] for tx in outgoing),
            "tx_count": len(incoming) + len(outgoing),
            "incoming_count": len(incoming),
            "outgoing_count": len(outgoing),
            "chains_active": list(set(
                self._identify_chain(tx) for tx in incoming + outgoing
            )),
            "first_tx": min(
                (tx["timestamp"] for tx in incoming + outgoing if tx["timestamp"]),
                default=None,
            ),
            "last_tx": max(
                (tx["timestamp"] for tx in incoming + outgoing if tx["timestamp"]),
                default=None,
            ),
        }

    def generate_forensic_report(self, output_file=None):
        summary = self.analyze()

        lines = []
        lines.append("=" * 70)
        lines.append("BLOCKCHAIN FORENSIC ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append(f"Total Transactions: {summary['total_transactions']}")
        lines.append(f"Chains Analyzed: {summary['chains_analyzed']}")
        lines.append(f"Suspicious Patterns: {summary['suspicious_patterns']}")
        lines.append("")

        for chain_name, stats in summary["chain_breakdown"].items():
            lines.append(f"Chain: {chain_name}")
            lines.append(f"  Transactions: {stats['count']}")
            lines.append(f"  Volume: {stats['volume']:.6f}")
            lines.append(f"  Unique Addresses: {len(stats['addresses'])}")
            lines.append("")

        if self.suspicious_patterns:
            lines.append("-" * 70)
            lines.append("SUSPICIOUS ACTIVITY")
            lines.append("-" * 70)
            for pattern in self.suspicious_patterns[:50]:
                lines.append(f"  Type: {pattern['type']}")
                if "chain" in pattern:
                    lines.append(f"  Chain: {pattern['chain']}")
                if "hash" in pattern:
                    lines.append(f"  TX Hash: {pattern['hash']}")
                if "address" in pattern:
                    lines.append(f"  Address: {pattern['address']}")
                if "from" in pattern and "to" in pattern:
                    lines.append(f"  From: {pattern['from'][:32]}... -> To: {pattern['to'][:32]}...")
                if "value" in pattern:
                    lines.append(f"  Value: {pattern['value']}")
                if "description" in pattern:
                    lines.append(f"  Detail: {pattern['description']}")
                lines.append("")

        report = "\n".join(lines)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)
            logger.info("Forensic report saved to %s", output_file)

        return report

    def export_results(self, output_file, format="json"):
        results = {
            "summary": self.analyze(),
            "suspicious_patterns": self.suspicious_patterns,
            "address_profiles": {k: {
                "total_in": v["total_in"],
                "total_out": v["total_out"],
                "tx_count": v["tx_count"],
            } for k, v in self.address_profiles.items()},
            "supported_chains": list(SUPPORTED_CHAINS.keys()),
            "generated_at": datetime.now().isoformat(),
        }

        if format == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
        elif format == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["type", "chain", "hash", "address", "value", "description"])
                for pattern in self.suspicious_patterns:
                    writer.writerow([
                        pattern.get("type", ""),
                        pattern.get("chain", pattern.get("chain_id", "")),
                        pattern.get("hash", ""),
                        pattern.get("address", pattern.get("from", "")),
                        pattern.get("value", ""),
                        pattern.get("description", ""),
                    ])

        logger.info("Forensic results exported to %s (%s)", output_file, format)


def run(config=None):
    if config is None:
        config = {}

    input_file = config.get("input_file", None)
    if not input_file:
        logger.error("No input file specified")
        return None

    analyzer = BlockchainForensicAnalyzer(config)
    analyzer.load_from_file(input_file)
    analyzer.analyze()

    output_dir = config.get("output_dir") or "output"
    os.makedirs(output_dir, exist_ok=True)

    report = analyzer.generate_forensic_report()
    print(report)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_output = os.path.join(output_dir, f"forensic_analysis_{timestamp}.json")
    analyzer.export_results(json_output, format="json")

    return analyzer


if __name__ == "__main__":
    run()
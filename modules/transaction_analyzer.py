import json
import csv
import os
import re
from collections import defaultdict
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("transaction_analyzer")


class TransactionAnalyzer:
    def __init__(self, config=None):
        self.config = config or {}
        self.suspicious_threshold = self.config.get("suspicious_threshold", 10000)
        self.chain_id = self.config.get("chain_id", 1)
        self.rpc_url = self.config.get("rpc_url", "http://localhost:8545")
        self.transactions = []
        self.address_balances = defaultdict(float)
        self.address_tx_count = defaultdict(int)
        self.suspicious_patterns = []

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
        elif isinstance(data, dict) and "transactions" in data:
            self.transactions = data["transactions"]
        elif isinstance(data, dict) and "result" in data:
            self.transactions = data["result"]
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

    def analyze_transactions(self):
        self.address_balances.clear()
        self.address_tx_count.clear()
        self.suspicious_patterns.clear()

        for tx in self.transactions:
            normalized = self._normalize_tx(tx)
            from_addr = normalized["from"]
            to_addr = normalized["to"]
            value = normalized["value"]

            if from_addr:
                self.address_balances[from_addr] -= value
                self.address_tx_count[from_addr] += 1
            if to_addr:
                self.address_balances[to_addr] += value
                self.address_tx_count[to_addr] += 1

        self._detect_suspicious()

        return {
            "total_transactions": len(self.transactions),
            "unique_addresses": len(self.address_balances),
            "total_volume": sum(abs(b) for b in self.address_balances.values()),
            "suspicious_patterns": len(self.suspicious_patterns),
        }

    def _detect_suspicious(self):
        high_value_txs = [
            tx for tx in self.transactions
            if self._parse_value(tx.get("value", tx.get("amount", "0"))) > self.suspicious_threshold
        ]

        for tx in high_value_txs:
            self.suspicious_patterns.append({
                "type": "high_value",
                "hash": self._normalize_tx(tx)["hash"],
                "value": self._parse_value(tx.get("value", tx.get("amount", "0"))),
                "from": self._normalize_tx(tx)["from"],
                "to": self._normalize_tx(tx)["to"],
            })

        rapid_txs = {}
        for tx in self.transactions:
            from_addr = tx.get("from", tx.get("sender", ""))
            if from_addr not in rapid_txs:
                rapid_txs[from_addr] = []
            rapid_txs[from_addr].append(tx)

        for addr, txs in rapid_txs.items():
            if len(txs) > 50:
                self.suspicious_patterns.append({
                    "type": "high_frequency",
                    "address": addr,
                    "tx_count": len(txs),
                    "description": f"Address {addr[:16]}... has {len(txs)} transactions",
                })

        round_trips = self._detect_round_trips()
        self.suspicious_patterns.extend(round_trips)

    def _detect_round_trips(self):
        patterns = []
        address_flows = defaultdict(list)

        for tx in self.transactions:
            from_addr = tx.get("from", tx.get("sender", ""))
            to_addr = tx.get("to", tx.get("receiver", ""))
            value = self._parse_value(tx.get("value", tx.get("amount", "0")))
            if from_addr and to_addr and value > 0:
                address_flows[from_addr].append((to_addr, value, tx))

        for addr, flows in address_flows.items():
            outgoing = set(f[0] for f in flows)
            for target in outgoing:
                for _, _, return_tx in address_flows.get(target, []):
                    if return_tx.get("to", return_tx.get("receiver", "")) == addr:
                        patterns.append({
                            "type": "round_trip",
                            "address": addr,
                            "counterparty": target,
                            "description": f"Round-trip flow detected between {addr[:16]}... and {target[:16]}...",
                        })
                        break

        return patterns

    def trace_flow(self, address, depth=3):
        flow = []
        visited = set()

        def _trace(addr, current_depth):
            if current_depth > depth or addr in visited:
                return
            visited.add(addr)

            for tx in self.transactions:
                normalized = self._normalize_tx(tx)
                if normalized["from"] == addr:
                    flow.append({
                        "direction": "outgoing",
                        "hash": normalized["hash"],
                        "to": normalized["to"],
                        "value": normalized["value"],
                        "timestamp": normalized["timestamp"],
                    })
                    _trace(normalized["to"], current_depth + 1)
                elif normalized["to"] == addr:
                    flow.append({
                        "direction": "incoming",
                        "hash": normalized["hash"],
                        "from": normalized["from"],
                        "value": normalized["value"],
                        "timestamp": normalized["timestamp"],
                    })
                    _trace(normalized["from"], current_depth + 1)

        _trace(address, 0)
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

        return {
            "address": address,
            "balance": self.address_balances.get(address, 0),
            "tx_count": self.address_tx_count.get(address, 0),
            "incoming_count": len(incoming),
            "outgoing_count": len(outgoing),
            "total_received": sum(tx["value"] for tx in incoming),
            "total_sent": sum(tx["value"] for tx in outgoing),
            "first_tx": min(
                (tx["timestamp"] for tx in incoming + outgoing if tx["timestamp"]),
                default=None,
            ),
            "last_tx": max(
                (tx["timestamp"] for tx in incoming + outgoing if tx["timestamp"]),
                default=None,
            ),
        }

    def generate_report(self, output_file=None):
        summary = self.analyze_transactions()

        lines = []
        lines.append("=" * 70)
        lines.append("BLOCKCHAIN TRANSACTION ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append(f"Total Transactions: {summary['total_transactions']}")
        lines.append(f"Unique Addresses: {summary['unique_addresses']}")
        lines.append(f"Total Volume: {summary['total_volume']:.6f}")
        lines.append(f"Suspicious Patterns Detected: {summary['suspicious_patterns']}")
        lines.append("")

        if self.suspicious_patterns:
            lines.append("-" * 70)
            lines.append("SUSPICIOUS ACTIVITY")
            lines.append("-" * 70)
            for pattern in self.suspicious_patterns:
                lines.append(f"  Type: {pattern['type']}")
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
            logger.info("Transaction report saved to %s", output_file)

        return report

    def export_results(self, output_file, format="json"):
        results = {
            "summary": self.analyze_transactions(),
            "suspicious_patterns": self.suspicious_patterns,
            "address_balances": dict(self.address_balances),
            "generated_at": datetime.now().isoformat(),
        }

        if format == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
        elif format == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["type", "hash", "address", "value", "description"])
                for pattern in self.suspicious_patterns:
                    writer.writerow([
                        pattern.get("type", ""),
                        pattern.get("hash", ""),
                        pattern.get("address", pattern.get("from", "")),
                        pattern.get("value", ""),
                        pattern.get("description", ""),
                    ])

        logger.info("Results exported to %s (%s)", output_file, format)


def run(config=None):
    if config is None:
        config = {}

    input_file = config.get("input_file", None)
    if not input_file:
        logger.error("No input file specified")
        return None

    analyzer = TransactionAnalyzer(config)
    analyzer.load_from_file(input_file)
    analyzer.analyze_transactions()

    output_dir = config.get("output_dir") or "output"
    os.makedirs(output_dir, exist_ok=True)

    report = analyzer.generate_report()
    print(report)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_output = os.path.join(output_dir, f"tx_analysis_{timestamp}.json")
    analyzer.export_results(json_output, format="json")

    return analyzer


if __name__ == "__main__":
    run()
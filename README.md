# Security Automation Toolkit

A modular Python framework for infrastructure security testing, asset discovery, vulnerability validation, and fraud investigation.

## Modules

| Module | Description |
|--------|-------------|
| `network` | Port and service scanner for mapping internal network assets |
| `files` | Structured test file generator for DLP and data classification validation |
| `telegram` | Telegram-based relay for distributed agent communication |
| `vuln` | Metasploit RPC integration for automated vulnerability validation |
| `profile` | Device type and firmware identification for asset inventory |
| `txanalyze` | Blockchain transaction parser for fraud investigation |

## Quick Start

```bash
pip install -r requirements.txt

# Scan a network range
python main.py network --targets 10.0.0.0/24 --ports 22,80,443

# Generate test files for DLP testing
python main.py files --patterns credit_card,ssn,email --count 500

# Send a message via Telegram relay
python main.py telegram --send "Scan complete" --chat 12345

# Validate a target with Metasploit
python main.py vuln --target 192.168.1.100 --scan

# Profile devices on the network
python main.py profile --targets 10.0.0.1 10.0.0.2

# Analyze blockchain transactions
python main.py txanalyze --input blockchain_data.json
```

## Configuration

Edit `config/settings.yaml` to customize defaults for each module.

## Project Structure

```
security_automation_toolkit/
├── config/
│   └── settings.yaml
├── modules/
│   ├── network_discovery.py
│   ├── file_generator.py
│   ├── remote_communication.py
│   ├── vulnerability_bridge.py
│   ├── device_profiler.py
│   └── transaction_analyzer.py
├── utils/
│   ├── logger.py
│   └── config.py
├── main.py
├── requirements.txt
└── README.md
```
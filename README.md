# Security Automation Toolkit

A modular Python framework for infrastructure security testing, asset discovery, vulnerability validation, and fraud investigation. Includes an Attack Simulation Library for purple team exercises.

## Core Modules

| Module | CLI Command | Description |
|--------|-------------|-------------|
| `network` | `network` | Port and service scanner for mapping internal network assets |
| `files` | `files` | Structured test file generator for DLP and data classification validation |
| `telegram` | `telegram` | Telegram-based relay for distributed agent communication |
| `vuln` | `vuln` | Metasploit RPC integration for automated vulnerability validation |
| `profile` | `profile` | Device type and firmware identification for asset inventory |
| `txanalyze` | `txanalyze` | Blockchain transaction parser for fraud investigation |

## Attack Simulation Library

| Module | CLI Command | Description |
|--------|-------------|-------------|
| `email` | `email` | Phishing email campaign generator with URL obfuscation |
| `encrypt` | `encrypt` | File encryption and protected archive creator for ransomware testing |
| `creds` | `creds` | Credential harvesting form parser for password policy validation |
| `lateral` | `lateral` | Lateral movement trust relationship mapper |
| `exfil` | `exfil` | Data exfiltration simulation (DNS/HTTP/ICMP channels) |
| `persist` | `persist` | Persistence mechanism simulator for EDR coverage verification |
| `social` | `social` | Multi-channel social engineering toolkit with A/B testing |
| `forensic` | `forensic` | Enhanced blockchain forensic analyzer (multi-chain) |

## Quick Start

```bash
pip install -r requirements.txt

# Core modules
python main.py network --targets 10.0.0.0/24 --ports 22,80,443
python main.py files --patterns credit_card,ssn,email --count 500
python main.py telegram --send "Alert: scan complete" --chat 12345
python main.py vuln --target 192.168.1.100 --scan
python main.py profile --targets 10.0.0.1 10.0.0.2
python main.py txanalyze --input blockchain_data.json

# Attack Simulation Library
python main.py email --template phishing_credential --targets user1@corp.com user2@corp.com
python main.py encrypt --files secret.docx --password "Test123!" --mode encrypt
python main.py creds --mode parse --html-content "<form>..."
python main.py lateral --targets 10.0.0.1,10.0.0.2,10.0.0.3
python main.py exfil --data "sensitive data" --channel dns
python main.py persist --mode simulate --platform windows
python main.py social --channel email --targets user1@corp.com --ab-test
python main.py forensic --input blockchain_data.json --chains ethereum,bsc,polygon
```

## Configuration

Edit `config/settings.yaml` to customize defaults for each module.

## Project Structure

```
security_automation_toolkit/
├── config/
│   └── settings.yaml
├── modules/
│   ├── __init__.py
│   ├── network_discovery.py
│   ├── file_generator.py
│   ├── remote_communication.py
│   ├── vulnerability_bridge.py
│   ├── device_profiler.py
│   ├── transaction_analyzer.py
│   ├── email_campaign.py
│   ├── file_encryption.py
│   ├── credential_harvester.py
│   ├── lateral_movement.py
│   ├── data_exfiltration.py
│   ├── persistent_access.py
│   ├── social_engineering.py
│   └── blockchain_forensic.py
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── config.py
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```
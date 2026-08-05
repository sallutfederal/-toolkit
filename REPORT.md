# Security Automation Toolkit - Relatorio Completo

## Visao Geral

Sistema de automacao de seguranca com 14 modulos + bot Telegram interativo.
Ferramenta para testes de penetracao e avaliacao de seguranca ofensiva.

---

## Modulos

### 1. Network Discovery
- **Arquivo:** `modules/network_discovery.py`
- **Funcao:** Escaneamento de portas e servicos em rede
- **Comando:** `/scan <target> <portas>`
- **Config:** targets, ports, timeout, max_threads

### 2. File Generator
- **Arquivo:** `modules/file_generator.py`
- **Funcao:** Geracao de arquivos de teste (DLP testing)
- **Comando:** `/generate <tipo> <qtd>`
- **Formatos:** csv, json, xml, txt, pdf
- **Config:** patterns, record_count, formats, output_dir

### 3. Remote Communication
- **Arquivo:** `modules/remote_communication.py`
- **Funcao:** Relay Telegram para comunicacao entre agentes
- **Classes:** TelegramRelay, AgentRelay
- **Config:** bot_token, chat_id, api_url

### 4. Vulnerability Bridge
- **Arquivo:** `modules/vulnerability_bridge.py`
- **Funcao:** Bridge para Metasploit Framework
- **Comando:** `/vuln <target>`
- **Funcoes:** validate_target, list_modules, search_modules
- **Config:** target, port

### 5. Device Profiler
- **Arquivo:** `modules/device_profiler.py`
- **Funcao:** Identificacao de dispositivos e firmware
- **Comando:** `/profile <ip>`
- **Funcoes:** probe_device, classify_device
- **Config:** timeout

### 6. Transaction Analyzer
- **Arquivo:** `modules/transaction_analyzer.py`
- **Funcao:** Analise de transacoes blockchain
- **Comando:** `/chain <tx_hash>`
- **Funcoes:** analyze_transaction, trace_flow
- **Config:** depth

### 7. Email Campaign
- **Arquivo:** `modules/email_campaign.py`
- **Funcao:** Geracao de campanhas de phishing para testes
- **Config:** template, targets, count, smtp_host, smtp_port, smtp_user, smtp_pass

### 8. File Encryption
- **Arquivo:** `modules/file_encryption.py`
- **Funcao:** Criptografia de arquivos (AES/XOR)
- **Comando:** `/encrypt <arquivo>`
- **Config:** method (aes/xor)

### 9. Credential Harvester
- **Arquivo:** `modules/credential_harvester.py`
- **Funcao:** Parse de formularios HTML para deteccao de credenciais
- **Funcoes:** parse_html_form, classify_fields

### 10. Lateral Movement
- **Arquivo:** `modules/lateral_movement.py`
- **Funcao:** Mapeamento de relacoes de confianca em rede
- **Funcoes:** map_trust_relationships, analyze_lateral

### 11. Data Exfiltration
- **Arquivo:** `modules/data_exfiltration.py`
- **Funcao:** Simulacao de exfiltracao de dados
- **Comando:** `/exfil <tipo>`
- **Metodos:** dns, http, icmp
- **Config:** method, target

### 12. Persistent Access
- **Arquivo:** `modules/persistent_access.py`
- **Funcao:** Simulacao de mecanismos de persistencia
- **Comando:** `/persist <platform>`
- **Plataformas:** windows, linux, darwin
- **Config:** platform

### 13. Social Engineering
- **Arquivo:** `modules/social_engineering.py`
- **Funcao:** Kit de engenharia social multi-canal
- **Canais:** sms, whatsapp, email, multi_channel
- **Config:** channel, templates

### 14. Blockchain Forensic
- **Arquivo:** `modules/blockchain_forensic.py`
- **Funcao:** Analise forense blockchain multi-chain
- **Config:** chain

### 15. Login Scanner
- **Arquivo:** `modules/login_scanner.py`
- **Funcao:** Scan de endpoints de login e formularios
- **Comando:** `/login <domain>`
- **Funcoes:** scan_endpoints, analyze_forms, check_security_headers

### 16. Admin Config
- **Arquivo:** `modules/admin_config.py`
- **Funcao:** Gerenciamento de configuracao via Telegram
- **Comando:** `/admin`

---

## Comandos Telegram

| Comando | Descricao |
|---------|-----------|
| `/help` | Mostra todos os comandos |
| `/status` | Status do sistema |
| `/scan <target> <portas>` | Escanear rede |
| `/vuln <target>` | Verificar vulnerabilidades |
| `/profile <ip>` | Identificar dispositivo |
| `/login <domain>` | Scan de login endpoints |
| `/generate <tipo> <qtd>` | Gerar arquivos de teste |
| `/encrypt <arquivo>` | Criptografar arquivo |
| `/exfil <tipo>` | Simular exfiltracao |
| `/persist <platform>` | Simular persistencia |
| `/chain <tx_hash>` | Analisar transacao blockchain |
| `/admin` | Gerenciar configuracoes |
| `/admin show <modulo>` | Ver modulo especifico |
| `/admin set <mod> <chave> <valor>` | Alterar configuracao |
| `/admin reset [modulo]` | Resetar para padrao |
| `/admin modules` | Listar modulos |
| `/stop` | Parar o bot |

---

## Configuracao

### Variaveis de Ambiente
- `TELEGRAM_BOT_TOKEN` - Token do bot Telegram
- `TELEGRAM_CHAT_ID` - ID do chat

### Arquivos de Config
- `config/settings.yaml` - Configuracao principal
- `config/user_config.json` - Configuracao do usuario (via /admin)

---

## Estrutura do Projeto

```
security_automation_toolkit/
├── main.py                    # Entry point CLI
├── run_bot.bat                # Script para rodar bot
├── requirements.txt           # Dependencias
├── config/
│   ├── settings.yaml          # Config principal
│   └── user_config.json       # Config do usuario
├── modules/
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
│   ├── blockchain_forensic.py
│   ├── login_scanner.py
│   ├── telegram_bot.py
│   └── admin_config.py
├── utils/
│   ├── logger.py
│   └── config.py
├── output/                    # Arquivos gerados
└── logs/                      # Logs do sistema
```

---

## Dependencias

```
requests
pyyaml
reportlab
```

---

## Uso

### Modo CLI
```bash
python main.py network --targets 192.168.1.1 --ports 80,443
python main.py generate --types pdf --count 10
python main.py telegram --send "Mensagem" --chat 123456
```

### Modo Bot Telegram
```bash
run_bot.bat
```

---

## Seguranca

- Usar apenas em ambientes autorizados
- Tokens devem ser armazenados em variaveis de ambiente
- Nao committar tokens no git
- Rotacionar tokens periodicamente

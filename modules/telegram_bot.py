import time
import os
from datetime import datetime
from utils.logger import get_module_logger

logger = get_module_logger("telegram_bot")

HELP_TEXT = """*Security Automation Toolkit - Comandos Disponiveis*

*Rede e Seguranca:*
/scan <target> <portas> - Escanear rede (ex: `/scan 192.168.1.1 80,443`)
/vuln <target> - Verificar vulnerabilidades (ex: `/vuln 192.168.1.1`)
/profile <ip> - Identificar dispositivo (ex: `/profile 192.168.1.1`)
/login <domain> - Scan de login endpoints (ex: `/login example.com`)

*Arquivos e Criptografia:*
/generate <tipo> <qtd> - Gerar arquivos de teste (ex: `/generate pdf 10`)
/encrypt <arquivo> - Criptografar arquivo (ex: `/encrypt teste.txt`)
/exfil <tipo> - Simular exfiltracao (ex: `/exfil dns`)

*Persistencia e Analise:*
/persist <platform> - Simular persistencia (ex: `/persist windows`)
/chain <tx_hash> - Analisar transacao blockchain (ex: `/chain 0xabc...`)

*Configuracao:*
/admin - Gerenciar configuracoes do sistema

*Utilitarios:*
/help - Mostrar esta ajuda
/status - Status do sistema
/stop - Parar o bot"""


class TelegramBot:
    def __init__(self, telegram_relay, chat_id):
        self.relay = telegram_relay
        self.chat_id = chat_id
        self._running = False
        self._offset = 0
        self._handlers = {
            "/help": self._handle_help,
            "/status": self._handle_status,
            "/stop": self._handle_stop,
            "/scan": self._handle_scan,
            "/vuln": self._handle_vuln,
            "/profile": self._handle_profile,
            "/login": self._handle_login,
            "/generate": self._handle_generate,
            "/encrypt": self._handle_encrypt,
            "/exfil": self._handle_exfil,
            "/persist": self._handle_persist,
            "/chain": self._handle_chain,
            "/admin": self._handle_admin,
        }

    def start(self):
        self._running = True
        self._clear_pending_updates()
        self._send("Bot iniciado! Envie /help para ver os comandos.")
        logger.info("Bot started for chat %s", self.chat_id)
        self._poll_loop()

    def _clear_pending_updates(self):
        try:
            updates = self.relay.get_updates(offset=-1, timeout=0)
            if updates:
                self._offset = updates[-1]["update_id"] + 1
                logger.info("Cleared %d pending updates", len(updates))
        except Exception as e:
            logger.error("Failed to clear pending updates: %s", e)

    def stop(self):
        self._running = False
        self._send("Bot parado.")
        logger.info("Bot stopped for chat %s", self.chat_id)

    def _poll_loop(self):
        while self._running:
            try:
                updates = self.relay.get_updates(offset=self._offset, timeout=5)
                for update in updates:
                    self._offset = update["update_id"] + 1
                    msg = update.get("message")
                    if msg:
                        self._process_message(msg)
            except Exception as e:
                logger.error("Poll error: %s", e)
                time.sleep(2)

    def _process_message(self, msg):
        chat_id = str(msg.get("chat", {}).get("id"))
        if chat_id != self.chat_id:
            return

        from_user = msg.get("from", {})
        if from_user.get("is_bot"):
            return

        text = msg.get("text", "")
        if not text or not text.startswith("/"):
            return

        parts = text.strip().split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        handler = self._handlers.get(cmd)
        if handler:
            try:
                handler(args)
            except Exception as e:
                self._send(f"Erro ao executar {cmd}: {e}")
                logger.error("Handler error for %s: %s", cmd, e)
        else:
            self._send(f"Comando desconhecido: {cmd}\nEnvie /help para ver os comandos.")

    def _send(self, text):
        try:
            self.relay.send_message(self.chat_id, text)
        except Exception as e:
            logger.error("Failed to send message: %s", e)

    def _handle_help(self, args):
        self._send(HELP_TEXT)

    def _handle_status(self, args):
        status = (
            f"*Status do Sistema*\n"
            f"Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Chat ID: {self.chat_id}\n"
            f"Bot: Ativo"
        )
        self._send(status)

    def _handle_stop(self, args):
        self.stop()

    def _handle_scan(self, args):
        if not args:
            self._send("Uso: /scan <target> [portas]\nEx: `/scan 192.168.1.1 80,443`")
            return

        target = args[0]
        ports = None
        if len(args) > 1:
            ports = [int(p) for p in args[1].split(",")]

        self._send(f"Escaneando {target}...")
        try:
            from modules.network_discovery import discover_network, DEFAULT_PORTS
            scan_ports = ports or DEFAULT_PORTS
            results = discover_network([target], scan_ports, timeout=3, max_threads=50)
            open_ports = [str(r["port"]) for r in results if r.get("state") == "open"]
            if open_ports:
                self._send(f"Portas abertas em {target}: {', '.join(open_ports)}")
            else:
                self._send(f"Nenhuma porta aberta encontrada em {target}")
        except Exception as e:
            self._send(f"Erro no scan: {e}")

    def _handle_vuln(self, args):
        if not args:
            self._send("Uso: /vuln <target>\nEx: `/vuln 192.168.1.1`")
            return

        target = args[0]
        self._send(f"Verificando vulnerabilidades em {target}...")
        try:
            from modules.vulnerability_bridge import MetasploitBridge
            bridge = MetasploitBridge({})
            result = bridge.validate_target(target)
            self._send(f"Resultado: {result}")
        except Exception as e:
            self._send(f"Erro na verificacao: {e}")

    def _handle_profile(self, args):
        if not args:
            self._send("Uso: /profile <ip>\nEx: `/profile 192.168.1.1`")
            return

        ip = args[0]
        self._send(f"Identificando dispositivo {ip}...")
        try:
            from modules.device_profiler import probe_device
            result = probe_device(ip, timeout=5)
            self._send(f"Dispositivo: {result}")
        except Exception as e:
            self._send(f"Erro na identificacao: {e}")

    def _handle_login(self, args):
        if not args:
            self._send("Uso: /login <domain>\nEx: `/login example.com`")
            return

        target = args[0]
        self._send(f"Escaneando login endpoints em {target}...")
        try:
            from modules.login_scanner import LoginScanner
            scanner = LoginScanner()
            result = scanner.scan(target)
            report = result.get("report", "Erro ao gerar relatorio")
            self._send(report)
        except Exception as e:
            self._send(f"Erro no scan: {e}")

    def _handle_generate(self, args):
        if len(args) < 2:
            self._send("Uso: /generate <tipo> <qtd>\nTipos: csv, json, txt, pdf\nEx: `/generate pdf 1`")
            return

        file_type = args[0].lower()
        count = int(args[1])
        self._send(f"Gerando {count} arquivos {file_type}...")
        try:
            from modules.file_generator import generate_files
            output_path = generate_files(
                patterns=["credit_card", "ssn", "email"],
                record_count=count,
                output_dir="output/generated",
                formats=[file_type]
            )
            import glob
            files = glob.glob(os.path.join(output_path, f"*.{file_type}"))
            if files:
                for f in files:
                    self.relay.send_file(self.chat_id, f, caption=os.path.basename(f))
                    self._send(f"Arquivo enviado: {os.path.basename(f)}")
            else:
                self._send(f"Arquivos gerados em: {output_path}")
        except Exception as e:
            self._send(f"Erro na geracao: {e}")

    def _handle_encrypt(self, args):
        if not args:
            self._send("Uso: /encrypt <arquivo>\nEx: `/encrypt output/teste.txt`")
            return

        filepath = args[0]
        self._send(f"Criptografando {filepath}...")
        try:
            from modules.file_encryption import encrypt_file
            result = encrypt_file(filepath, method="aes")
            if os.path.isfile(result):
                self.relay.send_file(self.chat_id, result, caption=os.path.basename(result))
                self._send(f"Arquivo criptografado enviado: {os.path.basename(result)}")
            else:
                self._send(f"Criptografado: {result}")
        except Exception as e:
            self._send(f"Erro na criptografia: {e}")

    def _handle_exfil(self, args):
        if not args:
            self._send("Uso: /exfil <tipo>\nTipos: dns, http, icmp\nEx: `/exfil dns`")
            return

        method = args[0].lower()
        self._send(f"Simulando exfiltracao via {method}...")
        try:
            from modules.data_exfiltration import simulate_exfiltration
            result = simulate_exfiltration(method=method, target="127.0.0.1", data="test_data")
            self._send(f"Exfiltracao concluida: {result}")
        except Exception as e:
            self._send(f"Erro na exfiltracao: {e}")

    def _handle_persist(self, args):
        platform = args[0].lower() if args else "windows"
        self._send(f"Simulando persistencia em {platform}...")
        try:
            from modules.persistent_access import simulate_persistence
            result = simulate_persistence(platform=platform)
            self._send(f"Persistencia simulada: {result}")
        except Exception as e:
            self._send(f"Erro na persistencia: {e}")

    def _handle_chain(self, args):
        if not args:
            self._send("Uso: /chain <tx_hash>\nEx: `/chain 0xabc123...`")
            return

        tx_hash = args[0]
        self._send(f"Analisando transacao {tx_hash}...")
        try:
            from modules.transaction_analyzer import analyze_transaction
            result = analyze_transaction(tx_hash)
            self._send(f"Resultado: {result}")
        except Exception as e:
            self._send(f"Erro na analise: {e}")

    def _handle_admin(self, args):
        try:
            from modules.admin_config import handle_admin
            result = handle_admin(args)
            self._send(result)
        except Exception as e:
            self._send(f"Erro no admin: {e}")


def run_bot(config=None):
    from modules.remote_communication import TelegramRelay

    if config is None:
        config = {}

    tg_config = config.get("remote_communication", {}).get("telegram", {})
    bot_token = tg_config.get("bot_token", "")
    if not bot_token or bot_token.startswith("${"):
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")

    chat_id = config.get("remote_communication", {}).get("telegram", {}).get("chat_id", "")
    if not chat_id or chat_id.startswith("${"):
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    if not bot_token:
        raise ValueError("Telegram bot token is required. Set TELEGRAM_BOT_TOKEN env var.")
    if not chat_id:
        raise ValueError("Telegram chat_id is required. Set TELEGRAM_CHAT_ID env var.")

    relay = TelegramRelay(bot_token=bot_token)
    bot = TelegramBot(relay, chat_id)
    bot.start()

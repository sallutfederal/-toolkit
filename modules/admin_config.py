import os
import json
from datetime import datetime
from utils.logger import get_module_logger

logger = get_module_logger("admin_config")

CONFIG_FILE = "config/user_config.json"

DEFAULT_CONFIG = {
    "network": {
        "targets": ["127.0.0.1"],
        "ports": [22, 80, 443, 3389, 8080],
        "timeout": 3,
        "max_threads": 100,
    },
    "file_generator": {
        "patterns": ["credit_card", "ssn", "email"],
        "record_count": 100,
        "formats": ["csv", "json", "pdf"],
        "output_dir": "output/generated",
    },
    "vulnerability": {
        "target": "127.0.0.1",
        "port": 80,
    },
    "profiler": {
        "timeout": 5,
    },
    "transaction": {
        "depth": 3,
    },
    "email": {
        "template": "phishing_credential",
        "count": 1,
        "obfuscation": None,
        "smtp_host": None,
        "smtp_port": 587,
        "smtp_user": None,
        "smtp_pass": None,
    },
    "encryption": {
        "method": "aes",
    },
    "exfiltration": {
        "method": "dns",
        "target": "127.0.0.1",
    },
    "persistence": {
        "platform": "windows",
    },
    "social": {
        "channel": "email",
        "templates": ["invoice", "shipping", "password_reset"],
    },
    "blockchain": {
        "chain": "bitcoin",
    },
    "telegram": {
        "bot_token": "",
        "chat_id": "",
    },
}


class AdminConfig:
    def __init__(self):
        self.config = self._load_config()

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    saved = json.load(f)
                config = DEFAULT_CONFIG.copy()
                for module, settings in saved.items():
                    if module in config:
                        config[module].update(settings)
                return config
            except Exception as e:
                logger.error("Failed to load config: %s", e)
        return DEFAULT_CONFIG.copy()

    def _save_config(self):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)
        logger.info("Config saved to %s", CONFIG_FILE)

    def get(self, module, key=None):
        if module not in self.config:
            return None
        if key:
            return self.config[module].get(key)
        return self.config[module]

    def set(self, module, key, value):
        if module not in self.config:
            self.config[module] = {}
        self.config[module][key] = value
        self._save_config()

    def reset(self, module=None):
        if module:
            if module in DEFAULT_CONFIG:
                self.config[module] = DEFAULT_CONFIG[module].copy()
        else:
            self.config = DEFAULT_CONFIG.copy()
        self._save_config()

    def show_all(self):
        lines = ["*Configuracao Atual*\n"]
        for module, settings in self.config.items():
            lines.append(f"*{module.upper()}*")
            for key, value in settings.items():
                lines.append(f"  {key}: `{value}`")
            lines.append("")
        return "\n".join(lines)

    def show_module(self, module):
        if module not in self.config:
            return f"Modulo '{module}' nao encontrado"
        lines = [f"*Configuracao: {module.upper()}*\n"]
        for key, value in self.config[module].items():
            lines.append(f"  {key}: `{value}`")
        return "\n".join(lines)

    def parse_set(self, args):
        if len(args) < 2:
            return None, None, "Uso: /admin set <modulo> <chave> <valor>"

        module = args[0]
        key = args[1]
        raw_value = " ".join(args[2:]) if len(args) > 2 else None

        if module not in self.config:
            return None, None, f"Modulo '{module}' nao encontrado. Modulos: {', '.join(self.config.keys())}"
        if key not in self.config[module]:
            return None, None, f"Chave '{key}' nao encontrada em {module}. Chaves: {', '.join(self.config[module].keys())}"

        current = self.config[module][key]
        if isinstance(current, bool):
            value = raw_value.lower() in ("true", "1", "yes", "sim")
        elif isinstance(current, int):
            value = int(raw_value)
        elif isinstance(current, float):
            value = float(raw_value)
        elif isinstance(current, list):
            value = [v.strip() for v in raw_value.split(",")] if raw_value else []
        else:
            value = raw_value if raw_value else ""

        self.set(module, key, value)
        return module, key, value


_admin_config = None


def get_config():
    global _admin_config
    if _admin_config is None:
        _admin_config = AdminConfig()
    return _admin_config


def handle_admin(args):
    config = get_config()

    if not args:
        return config.show_all()

    cmd = args[0].lower()
    sub_args = args[1:]

    if cmd == "show":
        if sub_args:
            return config.show_module(sub_args[0])
        return config.show_all()

    elif cmd == "set":
        if len(sub_args) < 3:
            return "Uso: /admin set <modulo> <chave> <valor>\nEx: `/admin set network timeout 5`"
        module, key, result = config.parse_set(sub_args)
        if module:
            return f"Configurado: {module}.{key} = `{result}`"
        return result

    elif cmd == "reset":
        module = sub_args[0] if sub_args else None
        config.reset(module)
        if module:
            return f"Modulo '{module}' resetado para padrao"
        return "Toda configuracao resetada para padrao"

    elif cmd == "modules":
        lines = ["*Modulos disponiveis:*\n"]
        for module in config.config.keys():
            lines.append(f"  /admin show {module}")
        return "\n".join(lines)

    elif cmd == "help":
        return (
            "*Comandos Admin:*\n\n"
            "/admin - Ver toda configuracao\n"
            "/admin show <modulo> - Ver modulo especifico\n"
            "/admin set <modulo> <chave> <valor> - Alterar valor\n"
            "/admin reset [modulo] - Resetar para padrao\n"
            "/admin modules - Listar modulos\n"
            "/admin help - Esta ajuda\n\n"
            "*Modulos:* network, file_generator, vulnerability, profiler, "
            "transaction, email, encryption, exfiltration, persistence, "
            "social, blockchain, telegram"
        )

    else:
        return f"Comando desconhecido: {cmd}\nEnvie /admin help para ver os comandos"

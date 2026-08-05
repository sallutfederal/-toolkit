import os
import json
import random
from datetime import datetime
from utils.logger import get_module_logger

logger = get_module_logger("proxy_manager")

PROXY_FILE = "config/proxies.json"


class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self._load_proxies()

    def _load_proxies(self):
        if os.path.exists(PROXY_FILE):
            try:
                with open(PROXY_FILE, "r") as f:
                    data = json.load(f)
                self.proxies = data.get("proxies", [])
                logger.info("Loaded %d proxies", len(self.proxies))
            except Exception as e:
                logger.error("Failed to load proxies: %s", e)

    def _save_proxies(self):
        os.makedirs(os.path.dirname(PROXY_FILE), exist_ok=True)
        with open(PROXY_FILE, "w") as f:
            json.dump({"proxies": self.proxies}, f, indent=2)
        logger.info("Saved %d proxies", len(self.proxies))

    def add(self, proxy_str):
        if "://" not in proxy_str:
            proxy_str = f"http://{proxy_str}"

        proxy = {
            "url": proxy_str,
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active",
            "requests": 0,
            "errors": 0,
        }

        for p in self.proxies:
            if p["url"] == proxy["url"]:
                return None, "Proxy ja existe"

        self.proxies.append(proxy)
        self._save_proxies()
        return proxy, "Proxy adicionado"

    def remove(self, index):
        if 0 <= index < len(self.proxies):
            removed = self.proxies.pop(index)
            self._save_proxies()
            return removed, "Proxy removido"
        return None, "Indice invalido"

    def get_next(self):
        if not self.proxies:
            return None

        active = [p for p in self.proxies if p["status"] == "active"]
        if not active:
            return None

        proxy = active[self.current_index % len(active)]
        self.current_index += 1
        proxy["requests"] += 1
        return proxy["url"]

    def get_random(self):
        if not self.proxies:
            return None

        active = [p for p in self.proxies if p["status"] == "active"]
        if not active:
            return None

        proxy = random.choice(active)
        proxy["requests"] += 1
        return proxy["url"]

    def get_all(self):
        return self.proxies

    def clear(self):
        self.proxies = []
        self.current_index = 0
        self._save_proxies()

    def mark_error(self, proxy_url):
        for p in self.proxies:
            if p["url"] == proxy_url:
                p["errors"] += 1
                if p["errors"] >= 5:
                    p["status"] = "inactive"
                break

    def show_all(self):
        if not self.proxies:
            return "Nenhum proxy configurado"

        lines = []
        lines.append("═══════════════════════════════════════════")
        lines.append("  PROXIES CONFIGURADOS")
        lines.append("═══════════════════════════════════════════")
        lines.append("")

        for i, p in enumerate(self.proxies):
            status_icon = "+" if p["status"] == "active" else "-"
            lines.append(f"  [{i}] {status_icon} {p['url']}")
            lines.append(f"      Requests: {p['requests']} | Errors: {p['errors']}")
            lines.append("")

        lines.append("═══════════════════════════════════════════")
        lines.append(f"  Total: {len(self.proxies)} | Ativos: {len([p for p in self.proxies if p['status'] == 'active'])}")
        lines.append("═══════════════════════════════════════════")

        return "\n".join(lines)

    def get_proxies_dict(self):
        if not self.proxies:
            return None
        proxy_url = self.get_next()
        if not proxy_url:
            return None
        return {"http": proxy_url, "https": proxy_url}


_proxy_manager = None


def get_proxy_manager():
    global _proxy_manager
    if _proxy_manager is None:
        _proxy_manager = ProxyManager()
    return _proxy_manager


def handle_proxy(args):
    manager = get_proxy_manager()

    if not args:
        return manager.show_all()

    cmd = args[0].lower()
    sub_args = args[1:]

    if cmd == "add":
        if not sub_args:
            return (
                "Uso: /proxy add <proxy>\n\n"
                "Formatos:\n"
                "  /proxy add 127.0.0.1:8080\n"
                "  /proxy add http://ip:porta\n"
                "  /proxy add socks5://ip:porta"
            )
        proxy_str = sub_args[0]
        proxy, msg = manager.add(proxy_str)
        if proxy:
            return (
                "═══════════════════════════════════════════\n"
                "  PROXY ADICIONADO\n"
                "═══════════════════════════════════════════\n\n"
                f"  URL: {proxy['url']}\n"
                f"  Status: {proxy['status']}"
            )
        return msg

    elif cmd == "remove":
        if not sub_args:
            return "Uso: /proxy remove <indice>\nUse /proxy para ver os indices"
        try:
            index = int(sub_args[0])
            removed, msg = manager.remove(index)
            if removed:
                return (
                    "═══════════════════════════════════════════\n"
                    "  PROXY REMOVIDO\n"
                    "═══════════════════════════════════════════\n\n"
                    f"  URL: {removed['url']}"
                )
            return msg
        except ValueError:
            return "Indice invalido"

    elif cmd == "clear":
        manager.clear()
        return (
            "═══════════════════════════════════════════\n"
            "  PROXIES LIMPADOS\n"
            "═══════════════════════════════════════════"
        )

    elif cmd == "help":
        return (
            "═══════════════════════════════════════════\n"
            "  PROXY - AJUDA\n"
            "═══════════════════════════════════════════\n\n"
            "  /proxy\n"
            "    Ver todos os proxies\n\n"
            "  /proxy add <proxy>\n"
            "    Adicionar proxy\n\n"
            "  /proxy remove <indice>\n"
            "    Remover proxy\n\n"
            "  /proxy clear\n"
            "    Limpar todos os proxies\n\n"
            "  /proxy help\n"
            "    Esta ajuda\n\n"
            "───────────────────────────\n"
            "Formatos aceitos:\n"
            "  ip:porta\n"
            "  http://ip:porta\n"
            "  socks5://ip:porta"
        )

    else:
        return f"Comando '{cmd}' nao reconhecido\nEnvie /proxy help para ver os comandos"

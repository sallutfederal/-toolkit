import hashlib
import hmac
import json
import os
import time
import requests
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("remote_communication")


class TelegramRelay:
    def __init__(self, bot_token, api_url=None):
        if not bot_token:
            raise ValueError("Telegram bot token is required")

        self.bot_token = bot_token
        self.api_url = api_url or "https://api.telegram.org/bot"
        self.base_url = f"{self.api_url}{self.bot_token}"
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._message_queue = []

    def _request(self, method, params=None):
        url = f"{self.base_url}/{method}"
        try:
            response = self.session.post(url, json=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            if not data.get("ok"):
                error_code = data.get("error_code", "unknown")
                description = data.get("description", "No error description")
                raise RuntimeError(f"Telegram API error [{error_code}]: {description}")
            return data.get("result")
        except requests.exceptions.Timeout:
            logger.error("Telegram API request timed out: %s", method)
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error("Telegram API connection error: %s", e)
            raise
        except requests.exceptions.HTTPError as e:
            logger.error("Telegram API HTTP error: %s", e)
            raise

    def send_message(self, chat_id, text, parse_mode=None, disable_notification=False):
        if not chat_id:
            raise ValueError("chat_id is required")

        if len(text) > 4096:
            logger.warning("Message length %d exceeds 4096, truncating", len(text))
            text = text[:4096]

        params = {
            "chat_id": chat_id,
            "text": text,
            "disable_notification": disable_notification,
        }
        if parse_mode:
            params["parse_mode"] = parse_mode

        result = self._request("sendMessage", params)
        logger.info("Message sent to chat %s (message_id=%s)", chat_id, result.get("message_id"))
        return result

    def delete_message(self, chat_id, message_id):
        params = {"chat_id": chat_id, "message_id": message_id}
        try:
            result = self._request("deleteMessage", params)
            return True
        except Exception as e:
            logger.error("Failed to delete message %s: %s", message_id, e)
            return False

    def send_file(self, chat_id, file_path, caption=None):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        params = {"chat_id": chat_id}
        if caption:
            params["caption"] = caption

        with open(file_path, "rb") as f:
            files = {"document": (os.path.basename(file_path), f)}
            url = f"{self.base_url}/sendDocument"
            try:
                headers = {k: v for k, v in self.session.headers.items() if k.lower() != "content-type"}
                response = requests.post(url, data=params, files=files, headers=headers, timeout=60)
                response.raise_for_status()
                data = response.json()
                if not data.get("ok"):
                    raise RuntimeError(f"Telegram API error: {data.get('description')}")
                logger.info("File sent to chat %s", chat_id)
                return data.get("result")
            except requests.exceptions.RequestException as e:
                logger.error("Failed to send file to Telegram: %s", e)
                raise

    def get_updates(self, offset=None, timeout=30, limit=100):
        params = {"timeout": timeout, "limit": limit}
        if offset is not None:
            params["offset"] = offset

        result = self._request("getUpdates", params)
        return result or []

    def poll_messages(self, chat_id, callback, timeout=30):
        logger.info("Starting message poll for chat %s", chat_id)
        offset = None
        while True:
            try:
                updates = self.get_updates(offset=offset, timeout=timeout)
                for update in updates:
                    offset = update.get("update_id", 0) + 1
                    message = update.get("message", {})
                    if message.get("chat", {}).get("id") == chat_id:
                        text = message.get("text", "")
                        from_user = message.get("from", {}).get("username", "unknown")
                        logger.info("Received message from %s: %s", from_user, text[:100])
                        callback(message)
            except KeyboardInterrupt:
                logger.info("Message polling stopped by user")
                break
            except Exception as e:
                logger.error("Error polling messages: %s", e)
                time.sleep(5)

    def get_chat_info(self, chat_id):
        params = {"chat_id": chat_id}
        return self._request("getChat", params)

    def get_chat_members_count(self, chat_id):
        info = self.get_chat_info(chat_id)
        return info.get("members_count", 0) if info else 0


class AgentRelay:
    def __init__(self, relay_config=None):
        self.relay_config = relay_config or {}
        self.telegram = None
        self._agents = {}
        self._message_handlers = []

        if self.relay_config.get("telegram", {}).get("bot_token"):
            self._init_telegram()

    def _init_telegram(self):
        tg_config = self.relay_config.get("telegram", {})
        bot_token = tg_config.get("bot_token", "")
        if not bot_token or bot_token.startswith("${"):
            bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        api_url = tg_config.get("api_url")
        self.telegram = TelegramRelay(
            bot_token=bot_token,
            api_url=api_url,
        )
        logger.info("Telegram relay initialized")

    def register_agent(self, agent_id, agent_config):
        self._agents[agent_id] = agent_config
        logger.info("Agent registered: %s", agent_id)

    def add_handler(self, handler):
        self._message_handlers.append(handler)

    def send_to_agent(self, agent_id, message):
        if agent_id not in self._agents:
            raise ValueError(f"Agent '{agent_id}' is not registered")

        agent = self._agents[agent_id]
        chat_id = agent.get("chat_id")

        if not chat_id:
            raise ValueError(f"Agent '{agent_id}' has no chat_id configured")

        if self.telegram is None:
            raise RuntimeError("Telegram relay is not initialized")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [AGENT:{agent_id}] {message}"

        return self.telegram.send_message(chat_id, formatted)

    def broadcast(self, message, exclude_agent=None):
        results = {}
        for agent_id in self._agents:
            if exclude_agent and agent_id == exclude_agent:
                continue
            try:
                result = self.send_to_agent(agent_id, message)
                results[agent_id] = {"status": "sent", "result": result}
            except Exception as e:
                logger.error("Failed to send to agent %s: %s", agent_id, e)
                results[agent_id] = {"status": "failed", "error": str(e)}
        return results

    def route_message(self, agent_id, message):
        for handler in self._message_handlers:
            try:
                handler(agent_id, message)
            except Exception as e:
                logger.error("Handler error for agent %s: %s", agent_id, e)

    def get_agent_status(self, agent_id):
        if agent_id not in self._agents:
            return {"status": "unknown", "agent_id": agent_id}

        agent = self._agents[agent_id]
        chat_id = agent.get("chat_id")

        if not chat_id or self.telegram is None:
            return {"status": "configured", "agent_id": agent_id}

        try:
            info = self.telegram.get_chat_info(chat_id)
            return {"status": "active", "agent_id": agent_id, "chat_title": info.get("title")}
        except Exception as e:
            return {"status": "unreachable", "agent_id": agent_id, "error": str(e)}


def run(config=None):
    if config is None:
        config = {}

    relay_config = config.get("remote_communication", {})
    relay = AgentRelay(relay_config)

    logger.info("Remote Communication Module initialized")
    return relay


if __name__ == "__main__":
    run()
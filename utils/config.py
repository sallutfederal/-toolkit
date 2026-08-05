import yaml
import os
from pathlib import Path


def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "settings.yaml",
        )

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config or {}


def get_section(config, section, required=False):
    value = config.get(section)
    if required and value is None:
        raise KeyError(f"Required configuration section '{section}' is missing")
    return value or {}
import os
import json
import platform
import subprocess
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("persistent_access")


SUPPORTED_PLATFORMS = ("windows", "linux", "darwin")

PERSISTENCE_METHODS = {
    "windows": {
        "registry_run": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry_runonce": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "scheduled_task": "Task Scheduler",
        "startup_folder": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "service": "Windows Service",
    },
    "linux": {
        "cron": "/etc/cron.d /var/spool/cron",
        "systemd_service": "/etc/systemd/system",
        "bashrc": "~/.bashrc /etc/profile",
        "init_d": "/etc/init.d",
    },
    "darwin": {
        "launchd": "~/Library/LaunchAgents /Library/LaunchDaemons",
        "cron": "/usr/libexec/cron.d",
        "login_item": "~/Library/Preferences/com.apple.loginitems",
    },
}

AGENT_PAYLOADS = {
    "windows": {
        "extension": ".exe",
        "default_path": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "service_name": "WinUpdateSvc",
    },
    "linux": {
        "extension": "",
        "default_path": "/tmp/.systemd",
        "service_name": "systemd-resolved",
    },
    "darwin": {
        "extension": "",
        "default_path": "/tmp/.launchd",
        "service_name": "com.apple.system.resolved",
    },
}


def _get_platform():
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    return "unknown"


def _simulate_registry_persistence(agent_path, name="SecurityAgent"):
    return {
        "method": "registry_run",
        "key": PERSISTENCE_METHODS["windows"]["registry_run"],
        "value_name": name,
        "value_data": agent_path,
        "description": f"Adds {name} to registry Run key for auto-start",
    }


def _simulate_scheduled_task(agent_path, name="SecurityAgent", trigger="logon"):
    return {
        "method": "scheduled_task",
        "task_name": name,
        "trigger": trigger,
        "action": f'"{agent_path}" /background',
        "description": f"Creates scheduled task triggered on {trigger}",
    }


def _simulate_cron_persistence(agent_path, name="security_agent"):
    cron_entry = f"*/5 * * * * {agent_path} > /dev/null 2>&1"
    return {
        "method": "cron",
        "cron_entry": cron_entry,
        "target_file": "/etc/cron.d/security_agent",
        "description": f"Adds cron job running every 5 minutes",
    }


def _simulate_systemd_service(agent_path, name="security-agent"):
    service_content = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart={agent_path}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    return {
        "method": "systemd_service",
        "service_file": f"/etc/systemd/system/{name}.service",
        "service_content": service_content.strip(),
        "description": f"Creates systemd service for auto-start",
    }


def _simulate_startup_folder(agent_path):
    return {
        "method": "startup_folder",
        "path": PERSISTENCE_METHODS["windows"]["startup_folder"],
        "target": agent_path,
        "description": "Copies agent to user startup folder",
    }


def _simulate_bashrc(agent_path):
    return {
        "method": "bashrc",
        "target_file": "~/.bashrc",
        "injection": f"\n{agent_path} &\n",
        "description": "Appends agent launch to shell rc file",
    }


def _simulate_launchd(agent_path, name="security.agent"):
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{agent_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
    return {
        "method": "launchd",
        "plist_file": f"~/Library/LaunchAgents/{name}.plist",
        "plist_content": plist_content.strip(),
        "description": "Creates launchd agent for auto-start on macOS",
    }


def detect_persistence(platform=None):
    if platform is None:
        platform = _get_platform()

    detected = []
    methods = PERSISTENCE_METHODS.get(platform, {})

    for method_name, target_path in methods.items():
        detected.append({
            "method": method_name,
            "target_path": target_path,
            "platform": platform,
            "status": "detectable",
        })

    logger.info("Detected %d persistence methods for platform: %s", len(detected), platform)
    return detected


def simulate_persistence_installation(platform=None, agent_path=None, method=None):
    if platform is None:
        platform = _get_platform()

    if agent_path is None:
        agent_path = AGENT_PAYLOADS[platform]["default_path"]

    platform_payloads = AGENT_PAYLOADS.get(platform, {})
    available_methods = PERSISTENCE_METHODS.get(platform, {})

    simulations = []

    if platform == "windows":
        if method is None or method == "registry_run":
            simulations.append(_simulate_registry_persistence(agent_path))
        if method is None or method == "scheduled_task":
            simulations.append(_simulate_scheduled_task(agent_path))
        if method is None or method == "startup_folder":
            simulations.append(_simulate_startup_folder(agent_path))

    elif platform == "linux":
        if method is None or method == "cron":
            simulations.append(_simulate_cron_persistence(agent_path))
        if method is None or method == "systemd_service":
            simulations.append(_simulate_systemd_service(agent_path))
        if method is None or method == "bashrc":
            simulations.append(_simulate_bashrc(agent_path))

    elif platform == "darwin":
        if method is None or method == "launchd":
            simulations.append(_simulate_launchd(agent_path))
        if method is None or method == "cron":
            simulations.append(_simulate_cron_persistence(agent_path))

    for sim in simulations:
        sim["agent_path"] = agent_path
        sim["platform"] = platform
        sim["timestamp"] = datetime.now().isoformat()

    logger.info("Simulated %d persistence methods for %s", len(simulations), platform)
    return simulations


def verify_edr_coverage(persistence_methods):
    coverage_report = {
        "total_methods": len(persistence_methods),
        "detection_coverage": [],
        "gaps": [],
    }

    detection_rules = {
        "registry_run": "Monitor HKCU Run key modifications",
        "scheduled_task": "Monitor scheduled task creation",
        "startup_folder": "Monitor startup folder changes",
        "cron": "Monitor cron file modifications",
        "systemd_service": "Monitor systemd unit file creation",
        "bashrc": "Monitor shell rc file modifications",
        "launchd": "Monitor launchd plist creation",
    }

    for method in persistence_methods:
        method_name = method.get("method", "")
        rule = detection_rules.get(method_name, "No specific rule defined")
        coverage_report["detection_coverage"].append({
            "method": method_name,
            "edr_rule": rule,
            "covered": rule != "No specific rule defined",
        })
        if rule == "No specific rule defined":
            coverage_report["gaps"].append(method_name)

    coverage_rate = (
        (len(coverage_report["detection_coverage"]) - len(coverage_report["gaps"]))
        / len(coverage_report["detection_coverage"])
        * 100
        if coverage_report["detection_coverage"]
        else 0
    )
    coverage_report["coverage_rate"] = f"{coverage_rate:.1f}%"

    logger.info("EDR coverage: %.1f%% (%d/%d methods covered)", coverage_rate,
                len(coverage_report["detection_coverage"]) - len(coverage_report["gaps"]),
                len(coverage_report["detection_coverage"]))

    return coverage_report


def run(config=None):
    if config is None:
        config = {}

    mode = config.get("mode", "simulate")
    platform = config.get("platform", None)
    agent_path = config.get("agent_path", None)
    method = config.get("method", None)
    output_file = config.get("output_file", None)

    logger.info("Persistent Access Module starting...")
    logger.info("Mode: %s", mode)

    if mode == "detect":
        results = detect_persistence(platform)
    elif mode == "simulate":
        results = simulate_persistence_installation(platform, agent_path, method)
    elif mode == "verify_coverage":
        methods = config.get("persistence_methods", [])
        results = verify_edr_coverage(methods)
    else:
        raise ValueError(f"Unknown mode: {mode}")

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("Results saved to %s", output_file)

    return results


if __name__ == "__main__":
    run()
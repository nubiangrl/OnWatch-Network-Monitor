import json
import os
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

REMOTE_DEPLOYMENT_HISTORY_FILE = "data/remote_deployment_history.json"
DEFAULT_TIMEOUT = 45


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clean(value):
    if value is None:
        return ""
    return str(value).replace("\xa0", " ").strip()


def ensure_data_dir():
    os.makedirs("data", exist_ok=True)


def atomic_json_write(path, payload):
    ensure_data_dir()
    temp_path = f"{path}.tmp"
    with open(temp_path, "w") as f:
        json.dump(payload, f, indent=4)
    os.replace(temp_path, path)


def load_remote_deployment_history():
    ensure_data_dir()
    if not os.path.exists(REMOTE_DEPLOYMENT_HISTORY_FILE):
        atomic_json_write(REMOTE_DEPLOYMENT_HISTORY_FILE, [])
        return []
    try:
        with open(REMOTE_DEPLOYMENT_HISTORY_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def save_remote_deployment_history(history):
    if not isinstance(history, list):
        history = []
    atomic_json_write(REMOTE_DEPLOYMENT_HISTORY_FILE, history[:250])


def add_remote_deployment_history(entry):
    history = load_remote_deployment_history()
    history.insert(0, entry)
    save_remote_deployment_history(history)
    return entry


def get_remote_restore_config(config):
    remote = config.get("remote_restore", {}) if isinstance(config, dict) else {}
    if not isinstance(remote, dict):
        remote = {}
    defaults = remote.get("deployment_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    return {
        "enabled": bool(remote.get("enabled", True)),
        "phase": remote.get("phase", "12C.2"),
        "engine": remote.get("engine", "Remote Restore Engine"),
        "transport": remote.get("transport", "native_ssh_rsync"),
        "history_file": remote.get("history_file", REMOTE_DEPLOYMENT_HISTORY_FILE),
        "default_remote_backup_dir": remote.get("default_remote_backup_dir", "/opt/onwatch/backups"),
        "default_remote_restore_dir": remote.get("default_remote_restore_dir", "/opt/onwatch/restore-staging"),
        "deployment_defaults": {
            "create_snapshot_before_restore": bool(defaults.get("create_snapshot_before_restore", True)),
            "restart_services_after_restore": bool(defaults.get("restart_services_after_restore", False)),
            "verify_after_restore": bool(defaults.get("verify_after_restore", True)),
            "rollback_on_failure": bool(defaults.get("rollback_on_failure", True)),
            "remote_service_name": defaults.get("remote_service_name", "on-watch")
        }
    }


def get_remote_servers(config):
    remote = config.get("remote_restore", {}) if isinstance(config, dict) else {}
    servers = remote.get("remote_servers", [])
    if not isinstance(servers, list):
        return []
    normalized = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        item = dict(server)
        item.setdefault("name", "")
        item.setdefault("ip", "")
        item.setdefault("ssh_user", "onwatch")
        item.setdefault("ssh_port", 22)
        item.setdefault("auth_type", "key")
        item.setdefault("key_path", "")
        item.setdefault("remote_backup_dir", get_remote_restore_config(config)["default_remote_backup_dir"])
        item.setdefault("remote_restore_dir", get_remote_restore_config(config)["default_remote_restore_dir"])
        item.setdefault("service_name", get_remote_restore_config(config)["deployment_defaults"]["remote_service_name"])
        item.setdefault("enabled", True)
        item.pop("password", None)  # never expose passwords through APIs/templates
        normalized.append(item)
    return normalized


def get_remote_server_private(config, server_name):
    remote = config.get("remote_restore", {}) if isinstance(config, dict) else {}
    for server in remote.get("remote_servers", []):
        if clean(server.get("name")) == clean(server_name):
            return server
    return None


def get_remote_groups(config):
    remote = config.get("remote_restore", {}) if isinstance(config, dict) else {}
    groups = remote.get("deployment_groups", [])
    if not isinstance(groups, list):
        return []
    normalized = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        item = dict(group)
        item.setdefault("name", "")
        item.setdefault("description", "")
        item.setdefault("servers", [])
        item.setdefault("enabled", True)
        normalized.append(item)
    return normalized


def get_group_server_names(config, group_name):
    for group in get_remote_groups(config):
        if clean(group.get("name")) == clean(group_name):
            return group.get("servers", []) or []
    return []


def _ssh_base_command(server):
    port = str(server.get("ssh_port", 22))
    command = [
        "ssh",
        "-o", "BatchMode=yes" if server.get("auth_type", "key") == "key" else "BatchMode=no",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", port
    ]
    key_path = clean(server.get("key_path"))
    if server.get("auth_type", "key") == "key" and key_path:
        command.extend(["-i", os.path.expanduser(key_path)])
    return command


def _password_prefix(server):
    if server.get("auth_type", "key") != "password":
        return []
    password = server.get("password", "")
    if not password:
        raise RuntimeError("Password authentication selected, but no password is configured for this server")
    if shutil.which("sshpass") is None:
        raise RuntimeError("Password authentication requires sshpass. Install it or switch this server to SSH key authentication")
    return ["sshpass", "-p", password]


def _target(server):
    return f"{server.get('ssh_user', 'onwatch')}@{server.get('ip', '')}"


def run_command(command, timeout=DEFAULT_TIMEOUT):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "command": " ".join(shlex.quote(str(x)) for x in command)
    }


def ssh_run(server, remote_command, timeout=DEFAULT_TIMEOUT):
    command = _password_prefix(server) + _ssh_base_command(server) + [_target(server), remote_command]
    return run_command(command, timeout=timeout)


def rsync_file(server, local_path, remote_dir, timeout=180):
    if shutil.which("rsync") is None:
        return scp_file(server, local_path, remote_dir, timeout=timeout)
    port = str(server.get("ssh_port", 22))
    ssh_parts = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", port]
    key_path = clean(server.get("key_path"))
    if server.get("auth_type", "key") == "key" and key_path:
        ssh_parts.extend(["-i", os.path.expanduser(key_path)])
    command = _password_prefix(server) + [
        "rsync", "-avz", "--progress",
        "-e", " ".join(shlex.quote(part) for part in ssh_parts),
        local_path,
        f"{_target(server)}:{remote_dir.rstrip('/')}/"
    ]
    return run_command(command, timeout=timeout)


def scp_file(server, local_path, remote_dir, timeout=180):
    port = str(server.get("ssh_port", 22))
    command = _password_prefix(server) + [
        "scp",
        "-o", "StrictHostKeyChecking=accept-new",
        "-P", port
    ]
    key_path = clean(server.get("key_path"))
    if server.get("auth_type", "key") == "key" and key_path:
        command.extend(["-i", os.path.expanduser(key_path)])
    command.extend([local_path, f"{_target(server)}:{remote_dir.rstrip('/')}/"])
    return run_command(command, timeout=timeout)


def test_remote_server_connection(config, server_name):
    server = get_remote_server_private(config, server_name)
    if not server:
        return {"ok": False, "server": server_name, "error": "Remote server not found"}
    if not server.get("enabled", True):
        return {"ok": False, "server": server_name, "error": "Remote server is disabled"}
    try:
        result = ssh_run(server, "echo ONWATCH_REMOTE_OK && hostname && pwd", timeout=20)
        return {
            "ok": result["returncode"] == 0 and "ONWATCH_REMOTE_OK" in result.get("stdout", ""),
            "server": server_name,
            "ip": server.get("ip", ""),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", 1)
        }
    except Exception as e:
        return {"ok": False, "server": server_name, "ip": server.get("ip", ""), "error": str(e)}


def test_remote_group_connections(config, group_name):
    names = get_group_server_names(config, group_name)
    results = [test_remote_server_connection(config, name) for name in names]
    success = [item for item in results if item.get("ok")]
    failed = [item for item in results if not item.get("ok")]
    return {
        "ok": len(failed) == 0 and len(results) > 0,
        "group": group_name,
        "server_count": len(results),
        "success_count": len(success),
        "failure_count": len(failed),
        "results": results
    }


def resolve_targets(config, target_type, target_name):
    target_type = clean(target_type).lower()
    target_name = clean(target_name)
    names = []
    if target_type == "group":
        names = get_group_server_names(config, target_name)
        if not names:
            raise RuntimeError(f"Deployment group not found or empty: {target_name}")
    else:
        names = [target_name]
    targets = []
    for name in names:
        server = get_remote_server_private(config, name)
        if not server:
            targets.append({"name": name, "error": "Remote server not found"})
            continue
        targets.append(server)
    return targets


def merge_options(config, options):
    defaults = get_remote_restore_config(config).get("deployment_defaults", {})
    merged = dict(defaults)
    if isinstance(options, dict):
        merged.update(options)
    return merged


def deploy_backup_to_server(config, server, backup_path, requested_by="On Watch Dashboard", options=None):
    backup_path = os.path.abspath(backup_path)
    backup_name = os.path.basename(backup_path)
    opts = merge_options(config, options)
    remote_backup_dir = server.get("remote_backup_dir") or get_remote_restore_config(config)["default_remote_backup_dir"]
    remote_restore_dir = server.get("remote_restore_dir") or get_remote_restore_config(config)["default_remote_restore_dir"]
    service_name = server.get("service_name") or opts.get("remote_service_name", "on-watch")

    entry = {
        "time": now(),
        "phase": "12C.2",
        "action": "REMOTE_DEPLOYMENT",
        "requested_by": clean(requested_by),
        "server": clean(server.get("name")),
        "ip": clean(server.get("ip")),
        "backup": backup_name,
        "status": "STARTED",
        "steps": []
    }

    def step(name, command_result):
        ok = command_result.get("returncode") == 0
        entry["steps"].append({
            "name": name,
            "ok": ok,
            "returncode": command_result.get("returncode"),
            "stdout": command_result.get("stdout", "")[-1000:],
            "stderr": command_result.get("stderr", "")[-1000:]
        })
        if not ok:
            raise RuntimeError(f"{name} failed: {command_result.get('stderr') or command_result.get('stdout')}")

    try:
        if not server.get("enabled", True):
            raise RuntimeError("Remote server is disabled")
        if not os.path.exists(backup_path):
            raise RuntimeError("Local backup file does not exist")

        test = test_remote_server_connection(config, server.get("name"))
        if not test.get("ok"):
            raise RuntimeError(test.get("error") or test.get("stderr") or "SSH test failed")
        entry["steps"].append({"name": "ssh_connectivity_test", "ok": True, "stdout": test.get("stdout", "")[-1000:], "stderr": test.get("stderr", "")[-1000:]})

        mkdir_result = ssh_run(server, f"mkdir -p {shlex.quote(remote_backup_dir)} {shlex.quote(remote_restore_dir)}", timeout=30)
        step("prepare_remote_directories", mkdir_result)

        if opts.get("create_snapshot_before_restore", True):
            snapshot_cmd = (
                f"mkdir -p {shlex.quote(remote_backup_dir)}/snapshots && "
                f"tar -czf {shlex.quote(remote_backup_dir)}/snapshots/onwatch-pre-deploy-$(date +%Y%m%d-%H%M%S).tar.gz "
                f"-C {shlex.quote(remote_restore_dir)} . 2>/dev/null || true"
            )
            snap_result = ssh_run(server, snapshot_cmd, timeout=120)
            entry["steps"].append({"name": "remote_snapshot_before_deploy", "ok": snap_result.get("returncode") == 0, "stdout": snap_result.get("stdout", "")[-1000:], "stderr": snap_result.get("stderr", "")[-1000:]})

        transfer = rsync_file(server, backup_path, remote_backup_dir, timeout=240)
        step("transfer_backup_rsync", transfer)

        if opts.get("verify_after_restore", True):
            verify_cmd = f"test -s {shlex.quote(remote_backup_dir.rstrip('/') + '/' + backup_name)} && echo VERIFIED"
            verify = ssh_run(server, verify_cmd, timeout=30)
            step("verify_remote_backup", verify)

        # Phase 12C.2 deploys the restore archive safely to the remote DR host.
        # The actual restore execution is intentionally staged for Phase 12C.3.
        if opts.get("restart_services_after_restore", False):
            restart_cmd = f"sudo systemctl restart {shlex.quote(service_name)} 2>/dev/null || systemctl restart {shlex.quote(service_name)} 2>/dev/null || true"
            restart = ssh_run(server, restart_cmd, timeout=45)
            entry["steps"].append({"name": "optional_remote_service_restart", "ok": restart.get("returncode") == 0, "stdout": restart.get("stdout", "")[-1000:], "stderr": restart.get("stderr", "")[-1000:]})

        entry["status"] = "SUCCESS"
        entry["message"] = "Backup deployed to remote server successfully"
        return add_remote_deployment_history(entry)

    except Exception as e:
        entry["status"] = "FAILED"
        entry["error"] = str(e)
        entry["message"] = "Remote backup deployment failed"
        return add_remote_deployment_history(entry)


def deploy_backup_to_remote_targets(config, backup_path, target_type, target_name, requested_by="On Watch Dashboard", options=None):
    targets = resolve_targets(config, target_type, target_name)
    results = []
    for server in targets:
        if server.get("error"):
            entry = {
                "time": now(),
                "phase": "12C.2",
                "action": "REMOTE_DEPLOYMENT",
                "requested_by": clean(requested_by),
                "server": clean(server.get("name")),
                "backup": os.path.basename(backup_path),
                "status": "FAILED",
                "error": server.get("error"),
                "message": "Remote server could not be resolved",
                "steps": []
            }
            results.append(add_remote_deployment_history(entry))
        else:
            results.append(deploy_backup_to_server(config, server, backup_path, requested_by=requested_by, options=options))
    success = [item for item in results if item.get("status") == "SUCCESS"]
    failed = [item for item in results if item.get("status") != "SUCCESS"]
    batch = {
        "ok": len(failed) == 0 and len(results) > 0,
        "phase": "12C.2",
        "target_type": clean(target_type),
        "target_name": clean(target_name),
        "backup": os.path.basename(backup_path),
        "server_count": len(results),
        "success_count": len(success),
        "failure_count": len(failed),
        "results": results
    }
    add_remote_deployment_history({
        "time": now(),
        "phase": "12C.2",
        "action": "REMOTE_DEPLOYMENT_BATCH",
        "target_type": clean(target_type),
        "target_name": clean(target_name),
        "backup": os.path.basename(backup_path),
        "status": "SUCCESS" if batch["ok"] else "PARTIAL_OR_FAILED",
        "success_count": batch["success_count"],
        "failure_count": batch["failure_count"],
        "message": "Remote deployment batch completed"
    })
    return batch


def build_remote_restore_summary(config):
    history = load_remote_deployment_history()
    servers = get_remote_servers(config)
    groups = get_remote_groups(config)
    successes = [item for item in history if item.get("status") == "SUCCESS"]
    failures = [item for item in history if item.get("status") in ["FAILED", "PARTIAL_OR_FAILED"]]
    return {
        "enabled": get_remote_restore_config(config).get("enabled", True),
        "phase": "12C.2",
        "server_count": len(servers),
        "group_count": len(groups),
        "history_count": len(history),
        "success_count": len(successes),
        "failure_count": len(failures),
        "last_deployment": history[0] if history else None
    }

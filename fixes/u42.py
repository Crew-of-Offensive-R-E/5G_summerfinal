"""U-42 불필요한 RPC 서비스 비활성화 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    capture_service_states,
    pgrep_any,
    read_text,
    result,
    restore_backups,
    restore_service_states,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)
from server_policy import PolicyError, policy_for, require_string_list


CODE = "U-42"
TITLE = "불필요한 RPC 서비스 비활성화"

RPC_SERVICES = (
    "rpc-statd",
    "rpc-gssd",
    "rpcbind",
    "rpc.cmsd",
    "rpc.ttdbserverd",
    "sadmind",
    "rusersd",
    "walld",
    "sprayd",
    "rstatd",
    "rpc.nisd",
    "rexd",
    "rpc.pcnfsd",
    "rpc.rquotad",
    "cachefsd",
)

XINETD_SERVICES = (
    "rstatd",
    "rusersd",
    "walld",
    "sprayd",
    "rexd",
    "rpc-statd",
    "rpc-gssd",
    "rquotad",
)

XINETD_DIR = "/etc/xinetd.d"
PROCESS_MARKER = "rpcbind/rpc.statd (pgrep)"


def _xinetd_enabled(service):
    content = read_text(os.path.join(XINETD_DIR, service)) or ""
    disable_value = None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.search(r"\bdisable\s*=\s*(yes|no)\b", stripped, re.I)
        if match:
            disable_value = match.group(1).lower()
    return disable_value == "no"


def _get_disallowed(allowed):
    active = [service for service in RPC_SERVICES if service not in allowed and systemctl_is_active(service)]
    if not ({"rpcbind", "rpc-statd"} & allowed) and pgrep_any("rpcbind", "rpc.statd"):
        active.append(PROCESS_MARKER)
    active.extend(
        f"xinetd:{service}" for service in XINETD_SERVICES
        if service not in allowed and _xinetd_enabled(service)
    )
    return active


def _disable_xinetd_file(service, backups):
    path = os.path.join(XINETD_DIR, service)
    if not os.path.isfile(path):
        return None, False
    original = read_text(path)
    if original is None:
        return f"{path}: 읽기 실패", False
    updated = re.sub(
        r"(?im)^(\s*(?![#;]).*?\bdisable\s*=\s*)no\b",
        r"\1yes",
        original,
    )
    if updated == original:
        return None, False

    backup = backup_file(path)
    if backup is None:
        return f"{path}: 백업 실패로 변경하지 않음", False
    backups.append(backup)
    if not write_text(path, updated):
        return f"{path}: 쓰기 실패", False
    return None, True


def _restart_xinetd():
    if not systemctl_is_active("xinetd"):
        return None
    code, out, err = run_command(["systemctl", "restart", "xinetd"], timeout=20)
    if code != 0:
        return f"xinetd 재시작 실패({err or out or code})"
    return None


def fix(dry_run=False):
    try:
        allowed = set(require_string_list(policy_for(CODE), "allowed_rpc_services"))
    except PolicyError as exc:
        return result(CODE, TITLE, MANUAL, f"서버 정책 확인 필요: {exc}")
    unknown = sorted(allowed - (set(RPC_SERVICES) | set(XINETD_SERVICES)))
    if unknown:
        return result(CODE, TITLE, MANUAL, "정책의 알 수 없는 RPC 서비스명: " + summarize(unknown))

    before = _get_disallowed(allowed)
    if not before:
        return None
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: 비허용 RPC 서비스 비활성화 예정 — " + summarize(before))
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors, backups = [], []
    changed_services = [
        service for service in before
        if service != PROCESS_MARKER and not service.startswith("xinetd:")
    ]
    service_states = capture_service_states(changed_services)
    for service in before:
        if service == PROCESS_MARKER or service.startswith("xinetd:"):
            continue
        code, out, err = run_command(["systemctl", "disable", "--now", service], timeout=30)
        if code != 0:
            errors.append(f"{service}: 중지·비활성화 실패({err or out or code})")

    changed = False
    for item in before:
        if not item.startswith("xinetd:"):
            continue
        error, item_changed = _disable_xinetd_file(item.split(":", 1)[1], backups)
        if error:
            errors.append(error)
        changed = changed or item_changed
    if changed:
        error = _restart_xinetd()
        if error:
            errors.append(error)

    remaining = _get_disallowed(allowed)
    if errors or remaining:
        restore_errors = restore_backups(backups)
        restore_errors.extend(restore_service_states(service_states))
        details = []
        if errors:
            details.append("오류: " + summarize(errors))
        if remaining:
            details.append("남은 비허용 RPC 서비스: " + summarize(remaining))
        if restore_errors:
            details.append("설정 원복 오류: " + summarize(restore_errors))
        elif backups:
            details.append("xinetd 설정 원복 완료")
        if backups:
            details.append("백업: " + summarize(backups))
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(CODE, TITLE, FIXED, "Open5GS 정책상 비허용 RPC 서비스 비활성화 완료" + (f" | 백업: {summarize(backups)}" if backups else ""))

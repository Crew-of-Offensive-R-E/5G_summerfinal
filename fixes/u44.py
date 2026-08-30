"""U-44 tftp/talk/ntalk 서비스 비활성화 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    capture_service_states,
    is_listening_on_port,
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
from server_policy import PolicyError, policy_for, require_bool


CODE = "U-44"
TITLE = "tftp, talk 서비스 비활성화"

SERVICE_UNITS = ("tftp", "tftp.socket", "tftpd-hpa", "talk", "ntalk")
INETD_PATH = "/etc/inetd.conf"
XINETD_DIR = "/etc/xinetd.d"
XINETD_SERVICES = ("tftp", "talk", "ntalk")

PROCESS_MARKER = "tftpd (pgrep)"
TALK_PROCESS_MARKER = "talkd/ntalkd (pgrep)"
PORT_MARKER = "port 69 (tftp)"


def _is_inetd_service_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    tokens = stripped.split()
    return bool(tokens and tokens[0].lower() in XINETD_SERVICES)


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


def _service_allowed(name, tftp_required, talk_required):
    return (name in {"tftp", "tftp.socket", "tftpd-hpa"} and tftp_required) or (
        name in {"talk", "ntalk"} and talk_required
    )


def _get_disallowed(tftp_required, talk_required):
    active = [
        unit for unit in SERVICE_UNITS
        if not _service_allowed(unit, tftp_required, talk_required)
        and systemctl_is_active(unit)
    ]
    if not tftp_required and pgrep_any("tftpd", "in.tftpd"):
        active.append(PROCESS_MARKER)
    if not talk_required and pgrep_any("talkd", "in.talkd", "ntalkd", "in.ntalkd"):
        active.append(TALK_PROCESS_MARKER)
    if not tftp_required and is_listening_on_port(69):
        active.append(PORT_MARKER)

    inetd = read_text(INETD_PATH) or ""
    for line in inetd.splitlines():
        if not _is_inetd_service_line(line):
            continue
        name = line.strip().split()[0].lower()
        if not _service_allowed(name, tftp_required, talk_required):
            active.append(f"inetd:{name}")
    active.extend(
        f"xinetd:{service}" for service in XINETD_SERVICES
        if not _service_allowed(service, tftp_required, talk_required)
        and _xinetd_enabled(service)
    )
    return active


def _backup_and_write(path, original, updated, backups):
    if original == updated:
        return None
    backup = backup_file(path)
    if backup is None:
        return f"{path}: 백업 실패로 변경하지 않음"
    backups.append(backup)
    if not write_text(path, updated):
        return f"{path}: 쓰기 실패"
    return None


def _disable_inetd(backups, disabled_names):
    if not os.path.isfile(INETD_PATH):
        return None, False
    original = read_text(INETD_PATH)
    if original is None:
        return f"{INETD_PATH}: 읽기 실패", False

    output = []
    changed = False
    for line in original.splitlines(keepends=True):
        if (_is_inetd_service_line(line) and
                line.strip().split()[0].lower() in disabled_names):
            output.append(f"# U-44 disabled: {line}")
            changed = True
        else:
            output.append(line)
    if not changed:
        return None, False

    error = _backup_and_write(INETD_PATH, original, "".join(output), backups)
    return error, error is None


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
    error = _backup_and_write(path, original, updated, backups)
    return error, error is None


def _restart_if_active(unit):
    if not systemctl_is_active(unit):
        return None
    code, out, err = run_command(["systemctl", "restart", unit], timeout=20)
    if code != 0:
        return f"{unit}: 재시작 실패({err or out or code})"
    return None


def fix(dry_run=False):
    try:
        policy = policy_for(CODE)
        tftp_required = require_bool(policy, "tftp_pxe_required")
        talk_required = require_bool(policy, "talk_required")
    except PolicyError as exc:
        return result(CODE, TITLE, MANUAL, f"서버 정책 확인 필요: {exc}")

    before = _get_disallowed(tftp_required, talk_required)
    if not before:
        return None
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: 비허용 TFTP/talk 서비스 비활성화 예정 — " + summarize(before))
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors, backups = [], []
    changed_units = [
        unit for unit in before
        if unit not in (PROCESS_MARKER, TALK_PROCESS_MARKER, PORT_MARKER) and ":" not in unit
    ]
    service_states = capture_service_states(changed_units)
    for unit in before:
        if unit in (PROCESS_MARKER, TALK_PROCESS_MARKER, PORT_MARKER) or ":" in unit:
            continue
        code, out, err = run_command(["systemctl", "disable", "--now", unit], timeout=30)
        if code != 0:
            errors.append(f"{unit}: 중지·비활성화 실패({err or out or code})")

    disabled_names = {
        name for name in XINETD_SERVICES
        if not _service_allowed(name, tftp_required, talk_required)
    }
    inetd_error, inetd_changed = _disable_inetd(backups, disabled_names)
    if inetd_error:
        errors.append(inetd_error)

    xinetd_changed = False
    for service in disabled_names:
        error, changed = _disable_xinetd_file(service, backups)
        if error:
            errors.append(error)
        xinetd_changed = xinetd_changed or changed

    if inetd_changed:
        error = _restart_if_active("inetd.service")
        if error:
            errors.append(error)
    if xinetd_changed:
        error = _restart_if_active("xinetd.service")
        if error:
            errors.append(error)

    remaining = _get_disallowed(tftp_required, talk_required)
    if errors or remaining:
        restore_errors = restore_backups(backups)
        restore_errors.extend(restore_service_states(service_states))
        details = []
        if errors:
            details.append("오류: " + summarize(errors))
        if remaining:
            details.append("남은 비허용 서비스: " + summarize(remaining))
        if restore_errors:
            details.append("설정 원복 오류: " + summarize(restore_errors))
        elif backups:
            details.append("inetd/xinetd 설정 원복 완료")
        if backups:
            details.append("백업: " + summarize(backups))
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(CODE, TITLE, FIXED, "Open5GS 정책상 불필요한 TFTP/PXE·talk 서비스 비활성화 완료" + (f" | 백업: {summarize(backups)}" if backups else ""))

"""U-38 DoS 공격에 취약한 Simple TCP/UDP 서비스 비활성화 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    capture_service_states,
    read_text,
    result,
    restore_backups,
    restore_service_states,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-38"
TITLE = "DoS 공격에 취약한 서비스 비활성화"

DOS_SERVICES = ("echo", "discard", "daytime", "chargen")
INETD_PATH = "/etc/inetd.conf"
XINETD_DIR = "/etc/xinetd.d"


def _active_systemd_units():
    active = []
    for service in DOS_SERVICES:
        for unit in (f"{service}.service", f"{service}.socket"):
            if systemctl_is_active(unit):
                active.append(unit)
    return active


def _is_vulnerable_inetd_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    tokens = stripped.split()
    return bool(tokens and tokens[0].lower() in DOS_SERVICES)


def _xinetd_is_enabled(content):
    disable_value = None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.search(r"\bdisable\s*=\s*(yes|no)\b", stripped, re.I)
        if match:
            disable_value = match.group(1).lower()
    return disable_value == "no"


def _active_settings():
    active = [f"systemd:{unit}" for unit in _active_systemd_units()]

    inetd = read_text(INETD_PATH) or ""
    for line in inetd.splitlines():
        if _is_vulnerable_inetd_line(line):
            active.append(f"inetd:{line.strip().split()[0]}")

    for service in DOS_SERVICES:
        path = os.path.join(XINETD_DIR, service)
        content = read_text(path) or ""
        if _xinetd_is_enabled(content):
            active.append(f"xinetd:{service}")
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


def _disable_inetd(backups):
    if not os.path.isfile(INETD_PATH):
        return None, False
    original = read_text(INETD_PATH)
    if original is None:
        return f"{INETD_PATH}: 읽기 실패", False

    output = []
    changed = False
    for line in original.splitlines(keepends=True):
        if _is_vulnerable_inetd_line(line):
            output.append(f"# U-38 disabled: {line}")
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
    code, out, err = run_command(["systemctl", "restart", unit], timeout=15)
    if code != 0:
        return f"{unit}: 재시작 실패({err or out or code})"
    return None


def fix(dry_run=False):
    before = _active_settings()
    if not before:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: Simple TCP/UDP 서비스 비활성화 예정 — {summarize(before)}",
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    active_units = _active_systemd_units()
    service_states = capture_service_states(active_units)

    for unit in _active_systemd_units():
        code, out, err = run_command(
            ["systemctl", "disable", "--now", unit], timeout=15
        )
        if code != 0:
            errors.append(f"{unit}: 중지·비활성화 실패({err or out or code})")

    inetd_error, inetd_changed = _disable_inetd(backups)
    if inetd_error:
        errors.append(inetd_error)

    xinetd_changed = False
    for service in DOS_SERVICES:
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

    remaining = _active_settings()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        restore_errors.extend(restore_service_states(service_states))
        details = []
        if errors:
            details.append(f"오류: {summarize(errors)}")
        if remaining:
            details.append(f"남은 활성 설정: {summarize(remaining)}")
        if restore_errors:
            details.append(f"원복 오류: {summarize(restore_errors)}")
        elif backups:
            details.append("변경 파일/메타데이터 원복 완료")
        if backups:
            details.append(f"백업: {summarize(backups)}")
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(
        CODE,
        TITLE,
        FIXED,
        "echo·discard·daytime·chargen 서비스 비활성화 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

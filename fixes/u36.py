"""U-36 r 계열 서비스 비활성화 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    capture_service_states,
    command_exists,
    read_text,
    result,
    restore_backups,
    restore_service_states,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-36"
TITLE = "r 계열 서비스 비활성화"

INETD_PATH = "/etc/inetd.conf"
XINETD_DIR = "/etc/xinetd.d"

R_SERVICE_NAMES = {"shell", "login", "exec", "rsh", "rlogin", "rexec"}
R_DAEMON_PATTERN = re.compile(r"\b(in\.)?(rshd|rlogind|rexecd)\b", re.I)

SYSTEMD_UNITS = (
    "rsh.service",
    "rsh.socket",
    "rlogin.service",
    "rlogin.socket",
    "rexec.service",
    "rexec.socket",
    "rsh-server.service",
)

SUPER_SERVER_UNITS = (
    "xinetd.service",
    "openbsd-inetd.service",
    "inetutils-inetd.service",
    "inetd.service",
)


def _unit_in_use(unit):
    if not command_exists("systemctl"):
        return False
    for action in ("is-active", "is-enabled"):
        code, _, _ = run_command(["systemctl", action, unit])
        if code == 0:
            return True
    return False


def _active_units():
    return [unit for unit in SYSTEMD_UNITS if _unit_in_use(unit)]


def _is_r_service_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    tokens = stripped.split()
    service = tokens[0].lower() if tokens else ""
    return service in R_SERVICE_NAMES or bool(R_DAEMON_PATTERN.search(stripped))


def _inetd_issues():
    if not os.path.isfile(INETD_PATH):
        return []
    text = read_text(INETD_PATH)
    if text is None:
        return [f"{INETD_PATH}: 읽기 실패"]
    return [
        f"{INETD_PATH}:{number}: r 계열 서비스 활성 설정"
        for number, line in enumerate(text.splitlines(), start=1)
        if _is_r_service_line(line)
    ]


def _xinetd_vulnerable_files():
    vulnerable = []
    errors = []
    if not os.path.isdir(XINETD_DIR):
        return vulnerable, errors

    try:
        names = sorted(os.listdir(XINETD_DIR))
    except (PermissionError, OSError) as exc:
        return vulnerable, [f"{XINETD_DIR}: 탐색 실패({exc})"]

    for name in names:
        path = os.path.join(XINETD_DIR, name)
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        if text is None:
            errors.append(f"{path}: 읽기 실패")
            continue

        related = name.lower() in R_SERVICE_NAMES
        disable_value = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            service_match = re.match(r"^\s*service\s+(\S+)", line, re.I)
            if service_match and service_match.group(1).lower() in R_SERVICE_NAMES:
                related = True
            if R_DAEMON_PATTERN.search(stripped):
                related = True
            disable_match = re.match(
                r"^\s*disable\s*=\s*(yes|no)\b", line, re.I
            )
            if disable_match:
                disable_value = disable_match.group(1).lower()

        if related and disable_value != "yes":
            vulnerable.append(path)

    return vulnerable, errors


def _issues():
    issues = [f"systemd 활성화: {unit}" for unit in _active_units()]
    issues.extend(_inetd_issues())
    files, errors = _xinetd_vulnerable_files()
    issues.extend(f"{path}: disable=yes 미설정" for path in files)
    issues.extend(errors)
    return issues


def _disable_inetd(backups):
    if not _inetd_issues() or not os.path.isfile(INETD_PATH):
        return []
    original = read_text(INETD_PATH)
    if original is None:
        return [f"{INETD_PATH}: 읽기 실패"]

    output = []
    changed = False
    for line in original.splitlines(keepends=True):
        if _is_r_service_line(line):
            output.append(f"# U-36 disabled: {line}")
            changed = True
        else:
            output.append(line)
    if not changed:
        return []

    backup = backup_file(INETD_PATH)
    if backup is None:
        return [f"{INETD_PATH}: 백업 실패로 변경하지 않음"]
    backups.append(backup)
    if not write_text(INETD_PATH, "".join(output)):
        return [f"{INETD_PATH}: 쓰기 실패"]
    return []


def _disable_xinetd_file(path, backups):
    original = read_text(path)
    if original is None:
        return [f"{path}: 읽기 실패"]

    output = []
    replaced = False
    for line in original.splitlines(keepends=True):
        if line.lstrip().startswith("#"):
            output.append(line)
        elif re.match(r"^\s*disable\s*=", line, re.I):
            indent = line[: len(line) - len(line.lstrip())]
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            output.append(f"{indent}disable = yes{newline}")
            replaced = True
        else:
            output.append(line)

    if not replaced:
        completed = []
        inserted = False
        for line in output:
            completed.append(line)
            if not inserted and "{" in line:
                newline = "\r\n" if line.endswith("\r\n") else "\n"
                completed.append(f"\tdisable = yes{newline}")
                inserted = True
        if not inserted:
            return [f"{path}: xinetd 서비스 블록을 찾지 못함"]
        output = completed

    updated = "".join(output)
    if updated == original:
        return []
    backup = backup_file(path)
    if backup is None:
        return [f"{path}: 백업 실패로 변경하지 않음"]
    backups.append(backup)
    if not write_text(path, updated):
        return [f"{path}: 쓰기 실패"]
    return []


def _restart_super_servers():
    errors = []
    for unit in SUPER_SERVER_UNITS:
        if not systemctl_is_active(unit):
            continue
        code, out, err = run_command(["systemctl", "restart", unit], timeout=15)
        if code != 0:
            errors.append(f"{unit}: 재시작 실패({err or out or code})")
    return errors


def fix(dry_run=False):
    before = _issues()
    if not before:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: r 계열 서비스 비활성화 예정 — {summarize(before)}",
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    active_units = _active_units()
    service_states = capture_service_states(active_units)
    for unit in _active_units():
        code, out, err = run_command(
            ["systemctl", "disable", "--now", unit], timeout=15
        )
        if code != 0:
            errors.append(f"{unit}: 중지·비활성화 실패({err or out or code})")

    errors.extend(_disable_inetd(backups))
    files, scan_errors = _xinetd_vulnerable_files()
    errors.extend(scan_errors)
    for path in files:
        errors.extend(_disable_xinetd_file(path, backups))
    errors.extend(_restart_super_servers())

    remaining = _issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        restore_errors.extend(restore_service_states(service_states))
        details = []
        if errors:
            details.append(f"오류: {summarize(errors)}")
        if remaining:
            details.append(f"남은 취약 설정: {summarize(remaining)}")
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
        "rlogin·rsh·rexec 서비스 중지 및 inetd/xinetd 비활성화 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

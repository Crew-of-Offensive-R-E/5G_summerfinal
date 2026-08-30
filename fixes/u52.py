"""U-52 Telnet 서비스 비활성화 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    is_listening_on_port,
    pgrep_any,
    read_text,
    result,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-52"
TITLE = "Telnet 서비스 비활성화"

TELNET_SVCS = ("telnet.socket", "telnet.service", "telnetd")
INETD_PATH = "/etc/inetd.conf"
XINETD_PATH = "/etc/xinetd.d/telnet"


def _is_inetd_telnet(line):
    stripped = line.strip()
    return bool(stripped and not stripped.startswith("#") and stripped.startswith("telnet"))


def _get_active():
    active = [f"systemd:{unit}" for unit in TELNET_SVCS if systemctl_is_active(unit)]
    if pgrep_any("telnetd", "in.telnetd"):
        active.append("process:telnetd")
    if is_listening_on_port(23):
        active.append("port:23")
    inetd = read_text(INETD_PATH) or ""
    if any(_is_inetd_telnet(line) for line in inetd.splitlines()):
        active.append("inetd:telnet")
    xinetd = read_text(XINETD_PATH) or ""
    if re.search(r"disable\s*=\s*no", xinetd, re.IGNORECASE):
        active.append("xinetd:telnet")
    return active


def _plan_file_changes():
    changes = []
    inetd = read_text(INETD_PATH)
    if inetd is not None:
        updated_lines = []
        for line in inetd.splitlines(keepends=True):
            updated_lines.append(f"# U-52 disabled: {line}" if _is_inetd_telnet(line) else line)
        updated = "".join(updated_lines)
        if updated != inetd:
            changes.append({"path": INETD_PATH, "original": inetd, "updated": updated})

    xinetd = read_text(XINETD_PATH)
    if xinetd is not None:
        # CORE는 주석 여부와 관계없이 이 문자열을 검사하므로 모든 일치 값을 정리한다.
        updated = re.sub(
            r"(disable\s*=\s*)no\b", r"\1yes", xinetd, flags=re.IGNORECASE
        )
        if updated != xinetd:
            changes.append({"path": XINETD_PATH, "original": xinetd, "updated": updated})
    return changes


def _unit_enabled(unit):
    code, out, _ = run_command(["systemctl", "is-enabled", unit], timeout=10)
    return code == 0 and out.strip() == "enabled"


def _restore_files(changes):
    errors = []
    for change in changes:
        if not write_text(change["path"], change["original"]):
            errors.append(f"{change['path']}: 원본 복구 실패")
    return errors


def _restore_units(states):
    errors = []
    for unit, state in states.items():
        if state["enabled"]:
            code, out, err = run_command(["systemctl", "enable", unit], timeout=15)
            if code != 0:
                errors.append(f"{unit}: enable 원복 실패({err or out or code})")
        if state["active"]:
            code, out, err = run_command(["systemctl", "start", unit], timeout=15)
            if code != 0:
                errors.append(f"{unit}: start 원복 실패({err or out or code})")
    return errors


def _restart_if_active(unit):
    if not systemctl_is_active(unit):
        return None
    code, out, err = run_command(["systemctl", "restart", unit], timeout=15)
    if code != 0:
        return f"{unit}: 재시작 실패({err or out or code})"
    return None


def _failure(message, written, states, backups):
    errors = _restore_files(written) + _restore_units(states)
    for unit in ("inetd.service", "xinetd.service"):
        restart_error = _restart_if_active(unit)
        if restart_error:
            errors.append(f"원복 후 {restart_error}")
    detail = message
    detail += " | " + ("원본 상태 복구 완료" if not errors else summarize(errors))
    if backups:
        detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FAILED, detail)


def fix(dry_run=False):
    before = _get_active()
    if not before:
        return None

    managed = any(item.startswith(("systemd:", "inetd:", "xinetd:")) for item in before)
    if not managed:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "telnetd 프로세스/23번 포트의 관리 주체를 확인해야 함 - " + summarize(before),
        )
    if not systemctl_is_active("sshd", "ssh"):
        return result(
            CODE,
            TITLE,
            MANUAL,
            "대체 원격 접속 수단인 SSH가 활성 상태가 아니므로 자동 중지 제외 - "
            + summarize(before),
        )

    changes = _plan_file_changes()
    active_units = [unit for unit in TELNET_SVCS if systemctl_is_active(unit)]
    if dry_run:
        targets = active_units + [change["path"] for change in changes]
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: Telnet 중지·비활성화 예정 - " + summarize(targets or before),
        )
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    backups = []
    for change in changes:
        backup = backup_file(change["path"])
        if backup is None:
            return result(
                CODE,
                TITLE,
                FAILED,
                f"{change['path']}: 백업 실패로 아무 설정도 변경하지 않음"
                + (f" | 완료된 백업: {summarize(backups)}" if backups else ""),
            )
        backups.append(backup)

    states = {
        unit: {"active": True, "enabled": _unit_enabled(unit)} for unit in active_units
    }
    for unit in active_units:
        code, out, err = run_command(
            ["systemctl", "disable", "--now", unit], timeout=15
        )
        if code != 0:
            return _failure(
                f"{unit}: 중지·비활성화 실패({err or out or code})",
                [],
                states,
                backups,
            )

    written = []
    for change in changes:
        if not write_text(change["path"], change["updated"]):
            return _failure(
                f"{change['path']}: 설정 쓰기 실패", written, states, backups
            )
        written.append(change)

    for path, unit in ((INETD_PATH, "inetd.service"), (XINETD_PATH, "xinetd.service")):
        if any(change["path"] == path for change in written):
            restart_error = _restart_if_active(unit)
            if restart_error:
                return _failure(restart_error, written, states, backups)

    remaining = _get_active()
    if remaining:
        return _failure(
            "조치 후 남은 Telnet 활성 상태: " + summarize(remaining),
            written,
            states,
            backups,
        )

    detail = "Telnet 서비스·inetd/xinetd 설정 비활성화 완료"
    if backups:
        detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FIXED, detail)

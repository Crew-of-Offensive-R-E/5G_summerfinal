"""U-49 BIND(named) 보안 업데이트 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    command_exists,
    glob_existing,
    result,
    restore_backups,
    run_command,
    summarize,
    systemctl_is_active,
)
from server_policy import PolicyError, policy_for, require_bool


CODE = "U-49"
TITLE = "DNS 보안 버전 패치"
PACKAGE = "bind9"

CONFIG_PATTERNS = (
    "/etc/bind/named.conf*",
    "/etc/bind/db.*",
    "/etc/bind/zones/*",
    "/var/lib/bind/*",
)


def _bind_installed():
    if not command_exists("named"):
        return False, ""
    code, out, _ = run_command(["named", "-v"], timeout=10)
    if code != 0 or not out:
        return False, ""
    return True, out.splitlines()[0]


def _package_installed():
    if not command_exists("dpkg-query"):
        return False
    code, out, _ = run_command(
        ["dpkg-query", "-W", "-f=${Status}", PACKAGE], timeout=10
    )
    return code == 0 and "install ok installed" in out


def _package_version():
    code, out, err = run_command(
        ["dpkg-query", "-W", "-f=${Version}", PACKAGE], timeout=10
    )
    if code != 0 or not out:
        return None, f"{PACKAGE} 버전 확인 실패({err or out or code})"
    return out.strip(), None


def _pending_upgrade():
    if not command_exists("apt-get"):
        return [], "apt-get 명령을 찾지 못함"
    code, out, err = run_command(
        ["apt-get", "-s", "install", "--only-upgrade", PACKAGE], timeout=60
    )
    if code != 0:
        return [], f"APT 모의 검사 실패({err or out or code})"

    pending = []
    for line in out.splitlines():
        match = re.match(r"^Inst\s+(\S+)", line)
        if match:
            pending.append(match.group(1))
    return sorted(set(pending)), None


def _backup_configs():
    backups = []
    errors = []
    for path in glob_existing(CONFIG_PATTERNS):
        if not os.path.isfile(path):
            continue
        backup = backup_file(path)
        if backup is None:
            errors.append(f"{path}: 백업 실패")
        else:
            backups.append(backup)
    return backups, errors


def _restart_bind_if_active():
    for unit in ("bind9", "named"):
        if not systemctl_is_active(unit):
            continue
        code, out, err = run_command(["systemctl", "restart", unit], timeout=30)
        if code != 0:
            return f"{unit} 재시작 실패({err or out or code})"
        return None
    return None


def fix(dry_run=False):
    try:
        auto_upgrade = require_bool(policy_for(CODE), "auto_upgrade")
    except PolicyError as exc:
        return result(CODE, TITLE, FAILED, f"서버 정책 오류: {exc}")
    if not auto_upgrade:
        return result(CODE, TITLE, FAILED, "서버 정책에서 자동 패키지 업그레이드가 승인되지 않음")
    if not command_exists("dpkg-query"):
        return result(CODE, TITLE, FAILED, "dpkg-query 명령을 찾지 못해 bind9 설치 상태를 판정할 수 없음")
    if not _package_installed():
        return None
    installed, version = _bind_installed()
    if not installed:
        return result(CODE, TITLE, FAILED, "bind9 패키지는 설치되어 있으나 named 버전을 확인할 수 없음")

    pending, check_error = _pending_upgrade()
    if check_error:
        return result(CODE, TITLE, FAILED, check_error)
    if not pending:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: BIND 보안 업데이트 예정({version}) — {summarize(pending)}",
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    package_version_before, version_error = _package_version()
    if version_error:
        return result(CODE, TITLE, FAILED, version_error)

    backups, backup_errors = _backup_configs()
    if backup_errors:
        return result(
            CODE,
            TITLE,
            FAILED,
            "BIND 설정 백업 실패로 패키지를 변경하지 않음: "
            + summarize(backup_errors),
        )

    code, out, err = run_command(
        ["apt-get", "install", "-y", "--only-upgrade", PACKAGE], timeout=600
    )
    if code != 0:
        rollback_errors = restore_backups(backups)
        detail = f"BIND 업데이트 실패({err or out or code})"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    if not command_exists("named-checkconf"):
        rollback_errors = restore_backups(backups)
        detail = "named-checkconf 명령을 찾지 못해 업데이트 후 설정을 검증할 수 없음"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        return result(CODE, TITLE, FAILED, detail)
    check_code, check_out, check_err = run_command(["named-checkconf"], timeout=30)
    if check_code != 0:
        rollback_errors = restore_backups(backups)
        detail = f"업데이트 후 named-checkconf 실패({check_err or check_out or check_code})"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        return result(CODE, TITLE, FAILED, detail)

    restart_error = _restart_bind_if_active()
    if restart_error:
        rollback_errors = restore_backups(backups)
        _restart_bind_if_active()
        detail = restart_error
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 후 재시작 시도 완료"
        return result(CODE, TITLE, FAILED, detail)

    remaining, verify_error = _pending_upgrade()
    if verify_error or remaining:
        rollback_errors = restore_backups(backups)
        _restart_bind_if_active()
        detail = (
            f"업데이트 후 검증 실패: {verify_error}"
            if verify_error
            else "업데이트 후에도 대기 패키지 존재: " + summarize(remaining)
        )
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 후 재시작 시도 완료"
        return result(CODE, TITLE, FAILED, detail)

    package_version_after, version_error = _package_version()
    installed_after, version_after = _bind_installed()
    if version_error or package_version_after == package_version_before or not installed_after:
        rollback_errors = restore_backups(backups)
        _restart_bind_if_active()
        detail = version_error or "업데이트 후 bind9 패키지 버전 변화 또는 named 실행 확인 실패"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 후 재시작 시도 완료"
        return result(CODE, TITLE, FAILED, detail)

    detail = f"BIND 보안 업데이트 완료: {version} → {version_after}"
    if backups:
        detail += f" | 설정 백업: {summarize(backups)}"
    else:
        detail += " | 존재하는 BIND 설정 파일 없음"
    return result(CODE, TITLE, FIXED, detail)

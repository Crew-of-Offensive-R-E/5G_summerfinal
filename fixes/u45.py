"""U-45 메일 서비스 보안 업데이트 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    command_exists,
    result,
    restore_backups,
    run_command,
    summarize,
)
from server_policy import PolicyError, policy_for, require_bool


CODE = "U-45"
TITLE = "메일 서비스 버전 점검"

MAIL_COMPONENTS = {
    "sendmail": {
        "commands": ("sendmail",),
        "packages": ("sendmail", "sendmail-bin", "sendmail-base", "sendmail-cf"),
    },
    "postfix": {
        "commands": ("postconf",),
        "packages": ("postfix",),
    },
    "exim4": {
        "commands": ("exim", "exim4"),
        "packages": (
            "exim4", "exim4-base", "exim4-config",
            "exim4-daemon-light", "exim4-daemon-heavy",
        ),
    },
}

SENDMAIL_CONFIGS = ("/etc/mail/sendmail.mc", "/etc/mail/sendmail.cf")
POSTFIX_CONFIGS = ("/etc/postfix/main.cf", "/etc/postfix/master.cf")
EXIM_CONFIGS = (
    "/etc/exim4/update-exim4.conf.conf",
    "/etc/exim4/exim4.conf.template",
)
CONFIG_FILES = {
    **{package: SENDMAIL_CONFIGS for package in MAIL_COMPONENTS["sendmail"]["packages"]},
    **{package: POSTFIX_CONFIGS for package in MAIL_COMPONENTS["postfix"]["packages"]},
    **{package: EXIM_CONFIGS for package in MAIL_COMPONENTS["exim4"]["packages"]},
}


def _package_installed(package):
    if not command_exists("dpkg-query"):
        return False
    code, out, _ = run_command(
        ["dpkg-query", "-W", "-f=${Status}", package], timeout=10
    )
    return code == 0 and "install ok installed" in out


def _installed_mail_packages():
    packages = []
    for component in MAIL_COMPONENTS.values():
        packages.extend(
            package
            for package in component["packages"]
            if _package_installed(package)
        )
    return sorted(set(packages))


def _package_versions(packages):
    versions = {}
    for package in packages:
        code, out, err = run_command(
            ["dpkg-query", "-W", "-f=${Version}", package], timeout=10
        )
        if code != 0 or not out:
            return None, f"{package} 버전 확인 실패({err or out or code})"
        versions[package] = out.strip()
    return versions, None


def _pending_upgrades(packages):
    if not packages:
        return [], None
    if not command_exists("apt-get"):
        return [], "apt-get 명령을 찾지 못함"

    code, out, err = run_command(
        ["apt-get", "-s", "install", "--only-upgrade", *packages], timeout=60
    )
    if code != 0:
        return [], f"APT 모의 검사 실패({err or out or code})"

    pending = []
    for line in out.splitlines():
        match = re.match(r"^Inst\s+(\S+)", line)
        if match:
            pending.append(match.group(1))
    return sorted(set(pending)), None


def _backup_configs(packages):
    backups = []
    errors = []
    for package in packages:
        for path in CONFIG_FILES.get(package, ()):
            if not os.path.isfile(path):
                continue
            backup = backup_file(path)
            if backup is None:
                errors.append(f"{path}: 백업 실패")
            else:
                backups.append(backup)
    return backups, errors


def fix(dry_run=False):
    try:
        auto_upgrade = require_bool(policy_for(CODE), "auto_upgrade")
    except PolicyError as exc:
        return result(CODE, TITLE, FAILED, f"서버 정책 오류: {exc}")
    if not auto_upgrade:
        return result(CODE, TITLE, FAILED, "서버 정책에서 자동 패키지 업그레이드가 승인되지 않음")
    if not command_exists("dpkg-query"):
        return result(CODE, TITLE, FAILED, "dpkg-query 명령을 찾지 못해 설치 패키지를 판정할 수 없음")
    packages = _installed_mail_packages()
    if not packages:
        return None

    pending, check_error = _pending_upgrades(packages)
    if check_error:
        return result(CODE, TITLE, FAILED, check_error)
    if not pending:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 메일 패키지 보안 업데이트 예정 — " + summarize(pending),
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    before_versions, version_error = _package_versions(packages)
    if version_error:
        return result(CODE, TITLE, FAILED, version_error)

    backups, backup_errors = _backup_configs(packages)
    if backup_errors:
        return result(
            CODE,
            TITLE,
            FAILED,
            "설정 백업 실패로 패키지를 변경하지 않음: " + summarize(backup_errors),
        )

    code, out, err = run_command(
        ["apt-get", "install", "-y", "--only-upgrade", *packages],
        timeout=600,
    )
    if code != 0:
        rollback_errors = restore_backups(backups)
        detail = f"메일 패키지 업데이트 실패({err or out or code})"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    remaining, verify_error = _pending_upgrades(packages)
    if verify_error or remaining:
        rollback_errors = restore_backups(backups)
        detail = (
            f"업데이트 후 검증 실패: {verify_error}"
            if verify_error
            else "업데이트 후에도 대기 패키지 존재: " + summarize(remaining)
        )
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    after_versions, version_error = _package_versions(packages)
    if version_error or not any(after_versions[name] != before_versions[name] for name in packages):
        rollback_errors = restore_backups(backups)
        detail = version_error or "업데이트 대상 패키지의 버전 변화가 확인되지 않음"
        if rollback_errors:
            detail += f" | 설정 원복 오류: {summarize(rollback_errors)}"
        elif backups:
            detail += " | 설정 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    changed = [name for name in packages if after_versions[name] != before_versions[name]]
    detail = "메일 패키지 업데이트 완료: " + summarize(changed)
    if backups:
        detail += f" | 설정 백업: {summarize(backups)}"
    else:
        detail += " | 존재하는 메일 설정 파일 없음"
    return result(CODE, TITLE, FIXED, detail)

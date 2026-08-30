"""U-48 SMTP EXPN/VRFY 명령 제한 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    command_exists,
    read_text,
    result,
    restore_backups,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-48"
TITLE = "expn, vrfy 명령어 제한"

SENDMAIL_CF = "/etc/mail/sendmail.cf"
POSTFIX_MAIN = "/etc/postfix/main.cf"


def _sendmail_privacy_options(content):
    options = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.match(r"^O\s*PrivacyOptions\s*=\s*(.*)$", stripped, re.I)
        if match:
            options = {
                item.strip().lower()
                for item in match.group(1).split(",")
                if item.strip()
            }
    return options


def _postfix_vrfy_value(content):
    value = None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^disable_vrfy_command\s*=\s*(\w+)", stripped, re.I)
        if match:
            value = match.group(1).lower()
    return value


def _get_issues():
    issues = []

    sendmail = read_text(SENDMAIL_CF) or ""
    sendmail_options = _sendmail_privacy_options(sendmail)
    if sendmail and not {"noexpn", "novrfy"}.issubset(sendmail_options):
        issues.append(
            {
                "kind": "sendmail",
                "detail": f"{SENDMAIL_CF}: noexpn/novrfy 없음",
            }
        )

    postfix = read_text(POSTFIX_MAIN) or ""
    if postfix:
        if _postfix_vrfy_value(postfix) != "yes":
            issues.append(
                {
                    "kind": "postfix",
                    "detail": f"{POSTFIX_MAIN}: disable_vrfy_command = yes 미설정",
                }
            )
    return issues


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


def _configure_sendmail(backups):
    original = read_text(SENDMAIL_CF)
    if original is None:
        return [f"{SENDMAIL_CF}: 읽기 실패"]

    active_options = _sendmail_privacy_options(original)
    needed = [name for name in ("noexpn", "novrfy") if name not in active_options]
    if not needed:
        return []

    pattern = re.compile(r"^O\s*PrivacyOptions\s*=\s*(.*)$", re.M)
    match = pattern.search(original)
    if match:
        options = match.group(1).strip().rstrip(",")
        updated = pattern.sub(
            f"O PrivacyOptions={options},{','.join(needed)}", original, count=1
        )
    else:
        separator = "" if not original or original.endswith("\n") else "\n"
        updated = (
            original
            + separator
            + "O PrivacyOptions=authwarnings,noexpn,novrfy\n"
        )

    error = _backup_and_write(SENDMAIL_CF, original, updated, backups)
    if error:
        return [error]

    if systemctl_is_active("sendmail"):
        code, out, err = run_command(["systemctl", "restart", "sendmail"], timeout=30)
        if code != 0:
            return [f"sendmail 재시작 실패({err or out or code})"]
    return []


def _configure_postfix(backups):
    original = read_text(POSTFIX_MAIN)
    if original is None:
        return [f"{POSTFIX_MAIN}: 읽기 실패"]

    pattern = re.compile(r"(?im)^\s*disable_vrfy_command\s*=\s*\w+")
    match = pattern.search(original)
    if _postfix_vrfy_value(original) == "yes":
        return []
    if match:
        updated = pattern.sub("disable_vrfy_command = yes", original)
    else:
        separator = "" if not original or original.endswith("\n") else "\n"
        updated = original + separator + "disable_vrfy_command = yes\n"

    error = _backup_and_write(POSTFIX_MAIN, original, updated, backups)
    if error:
        return [error]

    if command_exists("postfix"):
        code, out, err = run_command(["postfix", "reload"], timeout=30)
        if code != 0:
            return [f"postfix reload 실패({err or out or code})"]
    return []


def fix(dry_run=False):
    before = _get_issues()
    if not before:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: EXPN/VRFY 명령 제한 예정 — "
            + summarize([item["detail"] for item in before]),
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    kinds = {item["kind"] for item in before}
    if "sendmail" in kinds:
        errors.extend(_configure_sendmail(backups))
    if "postfix" in kinds:
        errors.extend(_configure_postfix(backups))

    remaining = _get_issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        if "sendmail" in kinds and systemctl_is_active("sendmail"):
            code, out, err = run_command(["systemctl", "restart", "sendmail"], timeout=30)
            if code != 0:
                restore_errors.append(f"원복 후 sendmail 재시작 실패({err or out or code})")
        if "postfix" in kinds and command_exists("postfix"):
            code, out, err = run_command(["postfix", "reload"], timeout=30)
            if code != 0:
                restore_errors.append(f"원복 후 postfix reload 실패({err or out or code})")
        details = []
        if errors:
            details.append(f"오류: {summarize(errors)}")
        if remaining:
            details.append(
                "남은 취약 설정: "
                + summarize([item["detail"] for item in remaining])
            )
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
        "Sendmail noexpn/novrfy 및 Postfix VRFY 제한 설정 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

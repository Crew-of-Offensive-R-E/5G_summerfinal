"""U-47 Sendmail/Postfix 오픈 릴레이 제한 조치."""

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


CODE = "U-47"
TITLE = "스팸 메일 릴레이 제한"

SENDMAIL_CF = "/etc/mail/sendmail.cf"
SENDMAIL_ACCESS = "/etc/mail/access"
POSTFIX_MAIN = "/etc/postfix/main.cf"
FAKE_MARKER = "VULNERABLE_FAKE_CONFIG"
RELAY_RULE = 'R$*\t\t$#error $@ 5.7.1 $: "550 Relaying denied"'


def _has_active_sendmail_relay_denial(content):
    return any(
        "relaying denied" in line.lower()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    )


def _postfix_restrictions(content):
    value = None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(
            r"^smtpd_recipient_restrictions\s*=\s*(.*)$", stripped, re.I
        )
        if match:
            value = match.group(1).lower()
    return value


def _get_issues():
    issues = []

    sendmail = read_text(SENDMAIL_CF) or ""
    if sendmail:
        if FAKE_MARKER in sendmail:
            issues.append(
                {
                    "kind": "sendmail_fake",
                    "detail": f"{SENDMAIL_CF}: 가짜 취약 설정 파일",
                }
            )
        elif not _has_active_sendmail_relay_denial(sendmail):
            issues.append(
                {
                    "kind": "sendmail_rule",
                    "detail": f"{SENDMAIL_CF}: 릴레이 차단 룰 없음",
                }
            )

    postfix = read_text(POSTFIX_MAIN) or ""
    postfix_restrictions = _postfix_restrictions(postfix)
    if postfix and (
        not postfix_restrictions
        or "reject_unauth_destination" not in postfix_restrictions
    ):
        issues.append(
            {
                "kind": "postfix",
                "detail": f"{POSTFIX_MAIN}: smtpd_recipient_restrictions 미설정",
            }
        )
    return issues


def _backup_existing(path, backups):
    backup = backup_file(path)
    if backup is None:
        return f"{path}: 백업 실패"
    backups.append(backup)
    return None


def _disable_fake_sendmail(backups):
    error = _backup_existing(SENDMAIL_CF, backups)
    if error:
        return [error]

    errors = []
    if systemctl_is_active("sendmail"):
        code, out, err = run_command(
            ["systemctl", "disable", "--now", "sendmail"], timeout=30
        )
        if code != 0:
            return [f"sendmail 중지·비활성화 실패({err or out or code})"]

    try:
        os.remove(SENDMAIL_CF)
    except (PermissionError, OSError) as exc:
        errors.append(f"{SENDMAIL_CF}: 가짜 설정 제거 실패({exc})")
    return errors


def _configure_sendmail(backups):
    original = read_text(SENDMAIL_CF)
    if original is None:
        return [f"{SENDMAIL_CF}: 읽기 실패"]

    errors = []
    if not _has_active_sendmail_relay_denial(original):
        separator = "" if not original or original.endswith("\n") else "\n"
        updated = original + separator + RELAY_RULE + "\n"
        error = _backup_existing(SENDMAIL_CF, backups)
        if error:
            return [error]
        if not write_text(SENDMAIL_CF, updated):
            return [f"{SENDMAIL_CF}: 쓰기 실패"]

    if systemctl_is_active("sendmail"):
        code, out, err = run_command(["systemctl", "restart", "sendmail"], timeout=30)
        if code != 0:
            errors.append(f"sendmail 재시작 실패({err or out or code})")
    return errors


def _configure_postfix(backups):
    original = read_text(POSTFIX_MAIN)
    if original is None:
        return [f"{POSTFIX_MAIN}: 읽기 실패"]
    restrictions = _postfix_restrictions(original)
    if restrictions and "reject_unauth_destination" in restrictions:
        return []

    safe_line = (
        "smtpd_recipient_restrictions = "
        "permit_mynetworks, reject_unauth_destination"
    )
    pattern = re.compile(r"(?im)^\s*smtpd_recipient_restrictions\s*=.*$")
    if pattern.search(original):
        updated = pattern.sub(safe_line, original)
    else:
        separator = "" if not original or original.endswith("\n") else "\n"
        updated = original + separator + safe_line + "\n"
    error = _backup_existing(POSTFIX_MAIN, backups)
    if error:
        return [error]
    if not write_text(POSTFIX_MAIN, updated):
        return [f"{POSTFIX_MAIN}: 쓰기 실패"]

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
            "dry-run: 메일 릴레이 제한 설정 예정 — "
            + summarize([item["detail"] for item in before]),
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    kinds = {item["kind"] for item in before}
    service_states = capture_service_states(["sendmail"]) if "sendmail_fake" in kinds else {}

    if "sendmail_fake" in kinds:
        errors.extend(_disable_fake_sendmail(backups))
    elif "sendmail_rule" in kinds:
        errors.extend(_configure_sendmail(backups))

    if "postfix" in kinds:
        errors.extend(_configure_postfix(backups))

    remaining = _get_issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        restore_errors.extend(restore_service_states(service_states))
        if "sendmail_rule" in kinds and systemctl_is_active("sendmail"):
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
        "Sendmail/Postfix 외부 릴레이 제한 설정 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

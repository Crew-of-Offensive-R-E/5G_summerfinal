"""U-46 일반 사용자의 메일 서비스 실행 방지 조치."""

import os
import re
import stat

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    read_text,
    result,
    restore_backups,
    run_command,
    set_file_mode,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-46"
TITLE = "일반 사용자의 메일 서비스 실행 방지"

SENDMAIL_CF = "/etc/mail/sendmail.cf"
POSTSUPER = "/usr/sbin/postsuper"
EXIQGREP = "/usr/sbin/exiqgrep"
ADMIN_COMMANDS = (POSTSUPER, EXIQGREP)


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


def _get_issues():
    issues = []

    content = read_text(SENDMAIL_CF) or ""
    if content and "restrictqrun" not in _sendmail_privacy_options(content):
        issues.append(
            {
                "kind": "sendmail",
                "path": SENDMAIL_CF,
                "detail": f"{SENDMAIL_CF}: restrictqrun 없음",
            }
        )

    for path in ADMIN_COMMANDS:
        if not os.path.exists(path):
            continue
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & stat.S_IXOTH:
                issues.append(
                    {
                        "kind": "mode",
                        "path": path,
                        "mode": mode,
                        "detail": f"{path}: 일반 사용자 실행 권한 있음({mode:03o})",
                    }
                )
        except (PermissionError, OSError) as exc:
            issues.append(
                {
                    "kind": "stat",
                    "path": path,
                    "detail": f"{path}: 상태 확인 실패({exc})",
                }
            )
    return issues


def _add_restrictqrun(backups):
    original = read_text(SENDMAIL_CF)
    if original is None:
        return f"{SENDMAIL_CF}: 읽기 실패", False
    if "restrictqrun" in _sendmail_privacy_options(original):
        return None, False

    pattern = re.compile(r"^O\s*PrivacyOptions\s*=\s*(.*)$", re.M | re.I)
    match = pattern.search(original)
    if match:
        options = match.group(1).strip().rstrip(",")
        updated = pattern.sub(
            f"O PrivacyOptions={options},restrictqrun", original, count=1
        )
    else:
        separator = "" if not original or original.endswith("\n") else "\n"
        updated = original + separator + "O PrivacyOptions=authwarnings,restrictqrun\n"

    backup = backup_file(SENDMAIL_CF)
    if backup is None:
        return f"{SENDMAIL_CF}: 백업 실패로 변경하지 않음", False
    backups.append(backup)
    if not write_text(SENDMAIL_CF, updated):
        return f"{SENDMAIL_CF}: 쓰기 실패", False
    return None, True


def _remove_other_execute(item, backups):
    path = item["path"]
    mode = item.get("mode")
    if mode is None:
        return f"{path}: 현재 권한을 확인하지 못해 변경하지 않음"

    backup = backup_file(path)
    if backup is None:
        return f"{path}: 백업 실패로 변경하지 않음"
    backups.append(backup)

    target_mode = mode & ~stat.S_IXOTH
    if not set_file_mode(path, target_mode):
        return f"{path}: other 실행 권한 제거 실패"
    return None


def _restart_sendmail():
    if not systemctl_is_active("sendmail"):
        return None
    code, out, err = run_command(["systemctl", "restart", "sendmail"], timeout=30)
    if code != 0:
        return f"sendmail 재시작 실패({err or out or code})"
    return None


def fix(dry_run=False):
    before = _get_issues()
    if not before:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 일반 사용자 메일 큐 실행 제한 예정 — "
            + summarize([item["detail"] for item in before]),
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    sendmail_changed = False

    for item in before:
        if item["kind"] == "sendmail":
            error, changed = _add_restrictqrun(backups)
            if error:
                errors.append(error)
            sendmail_changed = sendmail_changed or changed
        elif item["kind"] == "mode":
            error = _remove_other_execute(item, backups)
            if error:
                errors.append(error)
        else:
            errors.append(item["detail"])

    if sendmail_changed:
        error = _restart_sendmail()
        if error:
            errors.append(error)

    remaining = _get_issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        if sendmail_changed:
            reload_error = _restart_sendmail()
            if reload_error:
                restore_errors.append("원복 후 " + reload_error)
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
        "Sendmail restrictqrun 및 Postfix/Exim 관리 명령 실행 권한 조치 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

"""U-06 사용자 계정 su 기능 제한 조치."""

import grp
import re

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    read_text,
    backup_file,
    write_text,
    glob_existing,
)


CODE = "U-06"
TITLE = "사용자 계정 su 기능 제한"
TARGET = "/etc/pam.d/su"
SECURE_LINE = "auth required pam_wheel.so use_uid group=sudo"


def _pam_wheel_exists():
    return bool(glob_existing([
        "/lib/*/security/pam_wheel.so",
        "/usr/lib/*/security/pam_wheel.so",
        "/lib/security/pam_wheel.so",
        "/usr/lib/security/pam_wheel.so",
    ]))


def _restricted(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not re.search(r"\bpam_wheel\.so\b", stripped, re.IGNORECASE):
            continue
        if re.search(r"\buse_uid\b", stripped) and re.search(
            r"\bgroup=(?:sudo|wheel)\b", stripped, re.IGNORECASE
        ):
            return True
    return False


def _secure_text(text):
    pattern = re.compile(r"^\s*auth\s+\S+\s+.*pam_wheel\.so\b", re.IGNORECASE)
    lines = [line for line in text.splitlines() if not pattern.match(line)]
    include_index = next(
        (i for i, line in enumerate(lines)
         if re.search(r"^\s*@include\s+common-auth\b", line, re.IGNORECASE)),
        0,
    )
    lines.insert(include_index, SECURE_LINE)
    return "\n".join(lines) + "\n"


def fix(dry_run=False):
    text = read_text(TARGET)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일을 읽을 수 없음")
    if _restricted(text):
        return None
    if not _pam_wheel_exists():
        return result(CODE, TITLE, MANUAL, "pam_wheel.so 모듈 설치 확인 필요")
    try:
        grp.getgrnam("sudo")
    except KeyError:
        return result(CODE, TITLE, MANUAL, "Ubuntu 관리자 그룹 sudo가 없어 정책 확인 필요")

    if dry_run:
        return result(CODE, TITLE, FIXED, f"dry-run: {SECURE_LINE} 적용 예정")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, "PAM 설정 백업 실패")

    if not write_text(TARGET, _secure_text(text)):
        return result(CODE, TITLE, FAILED, "PAM 설정 쓰기 실패")

    updated = read_text(TARGET) or ""
    if not _restricted(updated):
        write_text(TARGET, text)
        return result(CODE, TITLE, FAILED, "su 제한 검증 실패로 원본 복원")

    return result(
        CODE, TITLE, FIXED,
        f"su 사용을 sudo 그룹으로 제한; 백업: {backup}",
    )


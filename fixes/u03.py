"""U-03 계정 잠금 임계값 설정 조치."""

import re
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    read_text,
    backup_file,
    write_text,
    command_exists,
    run_command,
    glob_existing,
    summarize,
)


CODE = "U-03"
TITLE = "계정 잠금 임계값 설정"
FAILLOCK_CONF = "/etc/security/faillock.conf"
COMMON_AUTH = "/etc/pam.d/common-auth"
COMMON_ACCOUNT = "/etc/pam.d/common-account"
PROFILE_FAIL = "/usr/share/pam-configs/kisa_faillock"
PROFILE_NOTIFY = "/usr/share/pam-configs/kisa_faillock_notify"

PROFILE_FAIL_TEXT = """Name: KISA pam_faillock failure recording
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail audit deny=10 unlock_time=120
"""

PROFILE_NOTIFY_TEXT = """Name: KISA pam_faillock precheck and reset
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth silent audit deny=10 unlock_time=120
Account-Type: Primary
Account:
 required pam_faillock.so
"""


def _module_exists():
    return bool(glob_existing([
        "/lib/*/security/pam_faillock.so",
        "/usr/lib/*/security/pam_faillock.so",
        "/lib/security/pam_faillock.so",
        "/usr/lib/security/pam_faillock.so",
    ]))


def _set_faillock_conf(text):
    pattern = re.compile(
        r"^\s*#?\s*(?:deny|unlock_time)\s*=|^\s*#?\s*(?:silent|audit)\s*$",
        re.IGNORECASE,
    )
    lines = [line for line in text.splitlines() if not pattern.match(line)]
    lines.extend(["silent", "audit", "deny = 10", "unlock_time = 120"])
    return "\n".join(lines) + "\n"


def _good():
    conf = read_text(FAILLOCK_CONF) or ""
    auth = read_text(COMMON_AUTH) or ""
    account = read_text(COMMON_ACCOUNT) or ""
    match = re.search(r"(?im)^\s*deny\s*=\s*(\d+)\s*$", conf)
    if not match or not 1 <= int(match.group(1)) <= 10:
        return False
    return (
        re.search(r"(?im)^\s*auth\s+.*pam_faillock\.so\s+preauth\b", auth)
        and re.search(r"(?im)^\s*auth\s+.*pam_faillock\.so\s+authfail\b", auth)
        and re.search(r"(?im)^\s*account\s+.*pam_faillock\.so\b", account)
    )


def _restore(originals):
    for path, text in originals.items():
        if text is None:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        else:
            write_text(path, text)


def fix(dry_run=False):
    if _good():
        return None
    if not _module_exists() or not command_exists("pam-auth-update"):
        return result(
            CODE, TITLE, MANUAL,
            "pam_faillock.so 및 pam-auth-update 설치 확인 후 적용 필요",
        )

    originals = {
        FAILLOCK_CONF: read_text(FAILLOCK_CONF),
        COMMON_AUTH: read_text(COMMON_AUTH),
        COMMON_ACCOUNT: read_text(COMMON_ACCOUNT),
        PROFILE_FAIL: read_text(PROFILE_FAIL),
        PROFILE_NOTIFY: read_text(PROFILE_NOTIFY),
    }
    # --force 실행 시 pam-auth-update가 common-* 파일을 함께 재생성할 수 있으므로
    # PAM 공통 설정 전체를 백업·복원 범위에 포함한다.
    for path in glob_existing(["/etc/pam.d/common-*"]):
        originals[path] = read_text(path)
    if originals[COMMON_AUTH] is None or originals[COMMON_ACCOUNT] is None:
        return result(CODE, TITLE, FAILED, "PAM 공통 설정 파일 읽기 실패")

    if dry_run:
        return result(
            CODE, TITLE, FIXED,
            "dry-run: 로그인 실패 10회, 120초 잠금 정책 적용 예정",
        )

    backups = []
    for path, old in originals.items():
        if old is None:
            continue
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    writes = {
        FAILLOCK_CONF: _set_faillock_conf(originals[FAILLOCK_CONF] or ""),
        PROFILE_FAIL: PROFILE_FAIL_TEXT,
        PROFILE_NOTIFY: PROFILE_NOTIFY_TEXT,
    }
    for path, content in writes.items():
        if not write_text(path, content):
            _restore(originals)
            return result(CODE, TITLE, FAILED, f"쓰기 실패로 원본 복원: {path}")

    code, _, error = run_command(
        [
            "env", "DEBIAN_FRONTEND=noninteractive",
            "pam-auth-update", "--force", "--enable",
            "kisa_faillock", "kisa_faillock_notify",
        ],
        timeout=120,
    )
    if code != 0 or not _good():
        _restore(originals)
        return result(
            CODE, TITLE, FAILED,
            f"PAM 적용 실패로 원본 복원: {error or '적용값 검증 실패'}",
        )

    return result(
        CODE, TITLE, FIXED,
        "pam_faillock 로그인 실패 10회/잠금 120초 적용; "
        f"백업: {summarize(backups)}",
    )

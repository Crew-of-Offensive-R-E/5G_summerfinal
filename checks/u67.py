"""U-67 로그 디렉터리 소유자 및 권한 설정"""
import os
import stat
from pathlib import Path

from check_common import (
    GOOD,
    VULN,
    result,
    summarize,
)

try:
    import pwd
except ImportError:
    pwd = None

CODE = "U-67"
TITLE = "로그 디렉터리 소유자 및 권한 설정"


def _owner_name(st):
    if pwd is None:
        return str(st.st_uid)
    try:
        return pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        return str(st.st_uid)


def _bad_log_files(log_dir):
    findings = []
    checked = 0
    for path in log_dir.rglob("*"):
        try:
            if not path.is_file() or path.is_symlink():
                continue
            st = path.stat()
        except (PermissionError, OSError):
            continue
        checked += 1
        mode = stat.S_IMODE(st.st_mode)
        owner = _owner_name(st)
        if owner not in ("root", "syslog", "mongodb") or (mode & stat.S_IWOTH):
            findings.append(f"{path}(owner={owner},mode={mode:03o})")
    return checked, findings


def check():
    log_dir = Path("/var/log")
    if not log_dir.is_dir():
        return result(CODE, TITLE, VULN, "/var/log 디렉터리를 찾지 못했습니다.")

    checked, findings = _bad_log_files(log_dir)

    # 점검 결과 반환 (읽기 전용)
    if not findings:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"/var/log 내 로그 파일 {checked}개가 허용 소유자 및 타인 쓰기 권한 없음을 만족합니다.",
        )

    return result(
        CODE,
        TITLE,
        VULN,
        f"/var/log 내 허용되지 않은 소유자 또는 타인 쓰기 권한이 존재합니다: {summarize(findings)}",
    )

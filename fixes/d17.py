"""D-17 Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한 조치

판단 기준(확인팀 checks/d17.py 기준): 감사 로그/시스템 로그 파일의 소유자가
mongod 또는 mongodb이고 권한이 640 이하면 양호. 소유자/권한이 부적절하면 취약.

조치: 로그 파일의 소유자를 mongod 서비스 실행 사용자로 변경하고 권한을 640으로 설정.
"""

import os
import stat

from fix_common import (
    FIXED, FAILED, MANUAL, result,
    read_text, set_file_owner, set_file_mode,
    get_service_file_user, get_mongod_process_user,
    MONGOD_CONF,
)

CODE = "D-17"
TITLE = "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"

VALID_OWNERS = ("mongod", "mongodb")
MAX_MODE = 0o640


def _parse_yaml_value(text, section, key):
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_section = stripped == f"{section}:"
            continue
        if in_section and stripped.startswith(f"{key}:"):
            return stripped.split(":", 1)[1].strip().strip("'\"")
    return None


def _check_and_fix_file(path, service_user, dry_run):
    """파일 소유자/권한을 점검하고 필요 시 수정. Returns (fixed, detail) or None if already ok."""
    if not path or not os.path.isfile(path):
        return None

    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    try:
        import pwd
        current_owner = pwd.getpwuid(st.st_uid).pw_name
    except (ImportError, KeyError):
        current_owner = str(st.st_uid)

    owner_ok = current_owner in VALID_OWNERS
    mode_ok = mode <= MAX_MODE and not (mode & stat.S_IWOTH)

    if owner_ok and mode_ok:
        return None  # 이미 양호

    if dry_run:
        return True, f"dry-run: {path} 소유자={current_owner}→{service_user}, 권한={mode:03o}→640"

    changes = []
    if not owner_ok:
        if set_file_owner(path, owner=service_user, group=service_user):
            changes.append(f"소유자 {current_owner}→{service_user}")
        else:
            return False, f"{path} 소유자 변경 실패"

    if not mode_ok:
        if set_file_mode(path, MAX_MODE):
            changes.append(f"권한 {mode:03o}→640")
        else:
            return False, f"{path} 권한 변경 실패"

    return True, f"{path}: {', '.join(changes)}"


def fix(dry_run=False):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    # 감사 기능 설정 여부 확인
    audit_dest = _parse_yaml_value(text, "auditLog", "destination")
    has_profiling = "operationProfiling" in text or "profile" in text
    if not audit_dest and not has_profiling:
        return result(CODE, TITLE, MANUAL,
                      "감사 기능 미설정 — 감사 로깅 활성화 후 권한 점검 필요")

    service_user = get_service_file_user() or get_mongod_process_user() or "mongodb"

    targets = []
    # auditLog 파일
    audit_path = _parse_yaml_value(text, "auditLog", "path")
    if audit_path:
        targets.append(audit_path)
    # systemLog 파일
    syslog_path = _parse_yaml_value(text, "systemLog", "path")
    if syslog_path:
        targets.append(syslog_path)

    if not targets:
        return result(CODE, TITLE, MANUAL, "로그 파일 경로를 확인할 수 없음")

    fixed_details = []
    for path in targets:
        r = _check_and_fix_file(path, service_user, dry_run)
        if r is None:
            continue
        ok, detail = r
        if not ok:
            return result(CODE, TITLE, FAILED, detail)
        fixed_details.append(detail)

    if not fixed_details:
        return None  # 이미 양호

    return result(CODE, TITLE, FIXED, "; ".join(fixed_details))

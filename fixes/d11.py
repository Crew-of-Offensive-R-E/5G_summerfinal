"""D-11 DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정 (탐지 전용)

판단 기준(확인팀 checks/d11.py 기준): 인증 비활성화면 취약. 인증 활성화 상태에서
비DBA 계정이 시스템 DB(admin, config, local)에 접근하거나 전역 역할을 보유하면 취약.

조치 방침: 비DBA 계정의 시스템 DB 접근 권한을 자동 회수하면 레플리카셋/샤딩
모니터링 등 정상 운영에 필요한 권한까지 제거될 수 있으므로, 해당 계정 목록을
보고하고 수동제외로 둔다.
"""

from fix_common import (
    MANUAL, result,
    is_auth_enabled, mongo_eval_json,
)

CODE = "D-11"
TITLE = "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"

_BROAD_ROLES = {
    "readAnyDatabase", "readWriteAnyDatabase", "dbAdminAnyDatabase",
    "root", "userAdminAnyDatabase", "__system",
}
_SYSTEM_DBS = {"admin", "config", "local"}


def fix(user=None, password=None, dry_run=False):
    if not is_auth_enabled():
        return result(CODE, TITLE, MANUAL, "인증 비활성화 — D-01 조치 선행 필요")

    if not user or not password:
        return result(CODE, TITLE, MANUAL, "관리자 자격증명 없어 사용자 목록 조회 불가")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin")'
        '.system.users.find({},{user:1,db:1,roles:1}).toArray())',
        user, password,
    )
    if data is None:
        return result(CODE, TITLE, MANUAL, "시스템 사용자 조회 실패(인증 필요)")

    if not isinstance(data, list):
        return result(CODE, TITLE, MANUAL, "사용자 목록 파싱 실패")

    flagged = []
    for u in data:
        uname = u.get("user", "")
        roles = u.get("roles", [])
        for r in roles:
            role_name = r.get("role", "") if isinstance(r, dict) else str(r)
            role_db = r.get("db", "") if isinstance(r, dict) else ""
            if role_name in _BROAD_ROLES and role_db == "admin":
                continue
            if role_name in _BROAD_ROLES or role_db in _SYSTEM_DBS:
                flagged.append(f"{uname}({role_name}@{role_db})")
                break

    if not flagged:
        return None  # 이미 양호

    listing = ", ".join(flagged)
    return result(
        CODE, TITLE, MANUAL,
        f"시스템 테이블 접근 가능 비DBA 계정: {listing} — "
        f"해당 계정의 업무상 시스템 DB 접근 필요 여부 확인 후, 불필요 시 "
        f"db.revokeRolesFromUser(\"계정명\", [{{role:\"역할\", db:\"DB명\"}}]) 명령으로 "
        f"수동 권한 회수 필요 (자동 회수 시 모니터링/레플리카셋 운영 장애 위험)"
    )

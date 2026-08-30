"""D-04 데이터베이스 관리자 권한을 최소화 (탐지 전용)

판단 기준(확인팀 checks/d04.py 기준): ADMIN_ROLES를 가진 계정이 2개 초과면 취약.

조치 방침: 관리자 권한을 자동 회수하면 정당한 DBA 계정까지 권한이 박탈되어
관리 기능이 마비될 수 있으므로, 과다 관리자 계정 목록을 보고하고 수동제외로 둔다.
"""

from fix_common import (
    MANUAL, result,
    is_auth_enabled, mongo_eval_json, ADMIN_ROLES,
)

CODE = "D-04"
TITLE = "데이터베이스 관리자 권한을 최소화"


def fix(user=None, password=None, dry_run=False):
    if not is_auth_enabled():
        return result(CODE, TITLE, MANUAL, "인증 비활성화 — D-01 조치 선행 필요")

    if not user or not password:
        return result(CODE, TITLE, MANUAL, "관리자 자격증명 없어 사용자 목록 조회 불가")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, MANUAL, "사용자 목록 조회 실패(인증 실패 또는 권한 부족)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, MANUAL, "사용자 목록 파싱 실패")

    admins = []
    for u in users:
        roles = u.get("roles", [])
        for r in roles:
            role_name = r.get("role", "") if isinstance(r, dict) else str(r)
            if role_name in ADMIN_ROLES:
                admins.append(f"{u.get('user', '')}({role_name})")
                break

    if len(admins) <= 2:
        return None  # 이미 양호

    listing = ", ".join(admins)
    return result(
        CODE, TITLE, MANUAL,
        f"관리자 권한 계정 과다({len(admins)}개): {listing} — "
        f"업무상 필요한 최소 관리자만 남기고, 나머지는 "
        f"db.revokeRolesFromUser(\"계정명\", [{{role:\"역할\", db:\"admin\"}}]) 명령으로 "
        f"수동 권한 회수 필요 (자동 회수 시 정당한 DBA 계정 권한 박탈 위험)"
    )

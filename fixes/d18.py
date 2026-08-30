"""D-18 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정 (탐지 전용)

판단 기준(확인팀 checks/d18.py 기준): 인증 비활성화면 취약. 비관리자 계정이
전역 과대 권한(readAnyDatabase, readWriteAnyDatabase 등)을 보유하면 취약.

조치 방침: 전역 권한을 자동 회수하면 정상 운영 중인 애플리케이션 계정의
접근이 차단될 수 있으므로, 해당 계정 목록을 보고하고 수동제외로 둔다.
"""

from fix_common import (
    MANUAL, result,
    is_auth_enabled, mongo_eval_json,
)

CODE = "D-18"
TITLE = "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"

PUBLIC_LIKE_ROLES = [
    "readAnyDatabase", "readWriteAnyDatabase",
    "dbAdminAnyDatabase", "userAdminAnyDatabase", "root",
]
DESIGNATED_ADMIN_ROLES = ("root", "userAdminAnyDatabase")


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

    designated_admins = set()
    for u in users:
        uname = u.get("user", "")
        for r in u.get("roles", []):
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in DESIGNATED_ADMIN_ROLES:
                designated_admins.add(uname)
                break

    flagged = []
    for u in users:
        uname = u.get("user", "")
        if uname in designated_admins:
            continue
        for r in u.get("roles", []):
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in PUBLIC_LIKE_ROLES:
                flagged.append(f"{uname}({rn})")

    if not flagged:
        return None  # 이미 양호

    listing = ", ".join(flagged)
    return result(
        CODE, TITLE, MANUAL,
        f"비관리자 계정에 전역 과대 권한 부여: {listing} — "
        f"해당 계정에 특정 DB 단위의 최소 권한만 부여하고, 전역 역할은 "
        f"db.revokeRolesFromUser(\"계정명\", [{{role:\"역할\", db:\"admin\"}}]) 명령으로 "
        f"수동 회수 필요 (자동 회수 시 운영 중인 애플리케이션 접근 차단 위험)"
    )

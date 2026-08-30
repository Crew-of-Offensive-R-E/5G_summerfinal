"""D-21 인가되지 않은 GRANT OPTION 사용 제한 (탐지 전용 / 자동 회수 안 함)

판단 기준(확인팀 5G_Check_Tool checks/d21.py 기준): 인증이 비활성화면 취약.
인증이 활성화된 상태에서 admin.getUsers()로 조회한 계정 중, root 또는
userAdminAnyDatabase 롤을 가진 "지정 관리자"가 아닌 계정이 userAdmin 또는
userAdminAnyDatabase 롤(GRANT OPTION과 동등한 권한 부여 권한)을 갖고 있으면 취약.

조치 방침: 관리자 Role 회수는 자동화하지 않는다. root 롤 없이 userAdminAnyDatabase만
가진 정식 관리자 계정까지 권한이 박탈돼 락아웃될 수 있으므로, flagged 계정이 발견되면
계정/DB/Role 목록만 보고하고 MANUAL(수동제외)로 둔다. --dry-run 여부와 무관하게
D-21에서는 Role을 실제로 변경하지 않는다.
"""

from fix_common import (
    MANUAL, result,
    is_auth_enabled, mongo_eval_json,
)

CODE = "D-21"
TITLE = "인가되지 않은 GRANT OPTION 사용 제한"
GRANT_ROLES = ["userAdmin", "userAdminAnyDatabase"]
# 지정 관리자로 인정하는 롤 (확인팀 5G_Check_Tool checks/d21.py 와 동일).
# userAdminAnyDatabase 는 MongoDB 표준 부트스트랩 관리자 롤이므로 지정 관리자로 본다.
DESIGNATED_ADMIN_ROLES = ("root", "userAdminAnyDatabase")


def _users(user, password):
    data = mongo_eval_json('EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password)
    if data is None:
        return None
    users = data.get("users", data) if isinstance(data, dict) else data
    return users if isinstance(users, list) else None


def _role_name(r):
    return r.get("role", "") if isinstance(r, dict) else str(r)


def _role_db(r, default="admin"):
    return r.get("db", default) if isinstance(r, dict) else default


def _flagged(users):
    designated_admins = {
        u.get("user", "") for u in users
        if any(_role_name(r) in DESIGNATED_ADMIN_ROLES for r in u.get("roles", []))
    }
    flagged = []
    for u in users:
        uname = u.get("user", "")
        if uname in designated_admins:
            continue
        for r in u.get("roles", []):
            rn = _role_name(r)
            if rn in GRANT_ROLES:
                flagged.append((uname, _role_db(r), rn))
    return flagged


def fix(user=None, password=None, dry_run=False):
    # D-21은 관리자 Role을 자동으로 회수하지 않는다(락아웃 위험). 탐지 결과만 보고한다.
    if not is_auth_enabled():
        return result(CODE, TITLE, MANUAL, "인증이 비활성화 상태 — D-01 조치(인증 활성화) 선행 필요")

    if not user or not password:
        return result(CODE, TITLE, MANUAL,
                      "관리자 자격증명(-u + --ask-password 또는 MONGO_ADMIN_USER/PASSWORD)이 없어 "
                      "사용자 목록을 조회할 수 없음 — 자동 조치 보류")

    users = _users(user, password)
    if users is None:
        return result(CODE, TITLE, MANUAL,
                      f"제공된 자격증명({user})으로 사용자 목록 조회 실패 — 인증 실패 또는 권한 부족")

    flagged = _flagged(users)
    if not flagged:
        return None  # 이미 양호

    listing = ", ".join(f"{u}@{db}({r})" for u, db, r in flagged)
    return result(
        CODE, TITLE, MANUAL,
        "비관리자(root 롤 없음) 계정이 GRANT 권한(userAdmin/userAdminAnyDatabase) 보유: "
        f"{listing} — 승인된 DBA 계정인지 확인 후, 아니라면 revokeRolesFromUser 명령으로 "
        "해당 Role을 수동 회수. (자동 회수 시 root 롤 없이 userAdminAnyDatabase만 가진 "
        "정식 관리자 계정의 권한까지 박탈돼 락아웃될 수 있어 D-21에서는 자동 조치하지 않음)"
    )

"""D-21 인가되지 않은 GRANT OPTION 사용 제한"""
from check_common import GOOD, VULN, NA, result, mongo_eval_json, is_auth_enabled, summarize

CODE = "D-21"
TITLE = "인가되지 않은 GRANT OPTION 사용 제한"

# userAdmin / userAdminAnyDatabase = 다른 사용자에게 역할 부여 가능 (GRANT OPTION 동등)
GRANT_ROLES = ["userAdmin", "userAdminAnyDatabase"]


def check(user=None, password=None):
    if not is_auth_enabled():
        return result(CODE, TITLE, VULN,
                      "인증 비활성화 — 모든 사용자가 권한 부여 가능(GRANT 동등)")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 조회 실패(미설치/인증)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    # 지정 관리자: root 역할 보유 계정
    designated_admins = set()
    for u in users:
        uname = u.get("user", "")
        roles = u.get("roles", [])
        for r in roles:
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in ("root", "userAdminAnyDatabase"):
                designated_admins.add(uname)
                break

    # 비관리자 계정 중 userAdmin / userAdminAnyDatabase 보유 여부 점검
    flagged = []
    for u in users:
        uname = u.get("user", "")
        if uname in designated_admins:
            continue
        roles = u.get("roles", [])
        for r in roles:
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in GRANT_ROLES:
                flagged.append(f"{uname}({rn})")

    if flagged:
        return result(CODE, TITLE, VULN,
                      f"비관리자 계정에 GRANT 권한 부여: {summarize(flagged)}")
    return result(CODE, TITLE, GOOD,
                  "GRANT 권한(userAdmin/userAdminAnyDatabase)이 지정 관리자에만 부여됨")

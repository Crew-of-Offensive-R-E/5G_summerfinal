"""D-18 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"""
from check_common import GOOD, VULN, NA, result, mongo_eval_json, is_auth_enabled, summarize

CODE = "D-18"
TITLE = "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"

# MongoDB에는 Public 역할이 없으나, 전역 과대 권한이 동등한 위험
PUBLIC_LIKE_ROLES = [
    "readAnyDatabase", "readWriteAnyDatabase",
    "dbAdminAnyDatabase", "userAdminAnyDatabase", "root",
]


def check(user=None, password=None):
    if not is_auth_enabled():
        return result(CODE, TITLE, VULN,
                      "인증 비활성화 — 모든 사용자가 전체 권한 보유(Public 동등)")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 조회 실패(미설치/인증)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    # 첫 번째 관리자(admin DB에서 root/userAdminAnyDatabase를 가진 최초 계정)를
    # 지정 관리자로 간주하고, 나머지 계정의 전역 과대 권한을 점검
    designated_admins = set()
    for u in users:
        uname = u.get("user", "")
        roles = u.get("roles", [])
        for r in roles:
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in ("root", "userAdminAnyDatabase"):
                designated_admins.add(uname)
                break

    flagged = []
    for u in users:
        uname = u.get("user", "")
        if uname in designated_admins:
            continue
        roles = u.get("roles", [])
        for r in roles:
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in PUBLIC_LIKE_ROLES:
                flagged.append(f"{uname}({rn})")

    if flagged:
        return result(CODE, TITLE, VULN,
                      f"비관리자 계정에 전역 과대 권한 부여: {summarize(flagged)}")
    return result(CODE, TITLE, GOOD,
                  "비관리자 계정에 전역 과대 권한(Public 동등) 없음")

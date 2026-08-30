"""D-24 Registry Procedure 권한 제한"""
from check_common import GOOD, VULN, NA, result, mongo_eval_json, is_auth_enabled, summarize

CODE = "D-24"
TITLE = "Registry Procedure 권한 제한"

# MongoDB에서 관리 명령 실행 가능한 위험 권한
_ADMIN_ACTIONS = {
    "clusterAdmin", "clusterManager", "hostManager",
    "root", "__system",
}


def check(user=None, password=None):
    if not is_auth_enabled():
        return result(CODE, TITLE, VULN,
                      "인증 비활성화 — 모든 사용자가 관리 명령 실행 가능")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 조회 실패(미설치/인증)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    # 지정 관리자 (root 역할 보유자)
    designated_admins = set()
    for u in users:
        uname = u.get("user", "")
        for r in u.get("roles", []):
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn == "root":
                designated_admins.add(uname)
                break

    # 비관리자 중 관리 명령 실행 가능 권한 보유 여부
    flagged = []
    for u in users:
        uname = u.get("user", "")
        if uname in designated_admins:
            continue
        for r in u.get("roles", []):
            rn = r.get("role", "") if isinstance(r, dict) else str(r)
            if rn in _ADMIN_ACTIONS:
                flagged.append(f"{uname}({rn})")

    if flagged:
        return result(CODE, TITLE, VULN,
                      f"비관리자 계정에 관리 명령 권한 부여: {summarize(flagged)}")
    return result(CODE, TITLE, GOOD,
                  "관리 명령 실행 권한이 관리자 계정에만 부여됨")

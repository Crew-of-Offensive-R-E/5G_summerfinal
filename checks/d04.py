"""D-04 데이터베이스 관리자 권한을 최소화"""
from check_common import GOOD, VULN, NA, result, mongo_eval_json, ADMIN_ROLES, summarize

CODE = "D-04"
TITLE = "데이터베이스 관리자 권한을 최소화"


def check(user=None, password=None):
    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 조회 실패(미설치/인증)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    admins = []
    for u in users:
        roles = u.get("roles", [])
        for r in roles:
            role_name = r.get("role", "") if isinstance(r, dict) else str(r)
            if role_name in ADMIN_ROLES:
                admins.append(f"{u.get('user', '')}({role_name})")
                break

    if len(admins) > 2:
        return result(CODE, TITLE, VULN,
                      f"관리자 권한 계정 과다({len(admins)}개): {summarize(admins)}")
    if admins:
        return result(CODE, TITLE, GOOD,
                      f"관리자 권한 계정: {summarize(admins)}")
    return result(CODE, TITLE, GOOD, "관리자 권한 계정 없음")

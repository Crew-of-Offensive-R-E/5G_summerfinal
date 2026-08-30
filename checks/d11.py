"""D-11 DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"""
from check_common import (GOOD, VULN, NA, result,
                    is_auth_enabled, mongo_eval_json, summarize, read_text,
                    MONGOD_CONF)

CODE = "D-11"
TITLE = "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"

_BROAD_ROLES = {
    "readAnyDatabase", "readWriteAnyDatabase", "dbAdminAnyDatabase",
    "root", "userAdminAnyDatabase", "__system",
}

_SYSTEM_DBS = {"admin", "config", "local"}


def check(user=None, password=None):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    if not is_auth_enabled():
        return result(CODE, TITLE, VULN,
                      "인증 비활성화 — 모든 사용자가 시스템 테이블 접근 가능")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin")'
        '.system.users.find({},{user:1,db:1,roles:1}).toArray())',
        user, password,
    )
    if data is None:
        return result(CODE, TITLE, NA, "시스템 사용자 조회 실패(인증 필요)")

    if not isinstance(data, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    flagged = []
    for u in data:
        uname = u.get("user", "")
        roles = u.get("roles", [])
        for r in roles:
            role_name = r.get("role", "") if isinstance(r, dict) else str(r)
            role_db = r.get("db", "") if isinstance(r, dict) else ""
            # admin DB의 관리 역할은 DBA로 간주하여 제외
            if role_name in _BROAD_ROLES and role_db == "admin":
                continue
            # 비DBA가 시스템 DB에 접근하거나 전역 역할 보유 시 플래그
            if role_name in _BROAD_ROLES or role_db in _SYSTEM_DBS:
                flagged.append(f"{uname}({role_name}@{role_db})")
                break

    if flagged:
        return result(CODE, TITLE, VULN,
                      f"시스템 테이블 접근 가능 비DBA 계정: {summarize(flagged)}")
    return result(CODE, TITLE, GOOD,
                  "비DBA 사용자의 시스템 테이블 접근 권한 미발견")

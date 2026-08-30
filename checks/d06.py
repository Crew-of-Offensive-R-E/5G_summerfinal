"""D-06 DB 사용자 계정을 개별적으로 부여하여 사용"""
from check_common import (GOOD, VULN, NA, MANUAL, result,
                    is_auth_enabled, mongo_eval_json, summarize)

CODE = "D-06"
TITLE = "DB 사용자 계정을 개별적으로 부여하여 사용"


def check(user=None, password=None):
    if not is_auth_enabled():
        return result(CODE, TITLE, VULN,
                      "인증 비활성화 — 모든 접속이 무인증이므로 개별 계정 부여 불가")

    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 사용자 목록 조회 실패(인증 필요)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    user_names = [u.get("user", "") for u in users]
    return result(CODE, TITLE, MANUAL,
                  f"등록 계정 {len(user_names)}개: {summarize(user_names)} — "
                  "[수동 점검 기준] ① 1인 1계정 원칙 준수 여부(공용 계정 사용 금지) "
                  "② 등록된 계정별 담당자 지정 및 문서화 여부 "
                  "③ 퇴직/이동 인원의 계정 즉시 삭제 또는 잠금 여부")

"""D-02 Demonstration 및 불필요한 계정을 제거하거나 잠금 설정 후 사용"""
from check_common import GOOD, VULN, NA, result, mongo_eval_json, SUSPICIOUS_PATTERNS, summarize

CODE = "D-02"
TITLE = "Demonstration 및 불필요한 계정을 제거하거나 잠금 설정 후 사용"


def check(user=None, password=None):
    data = mongo_eval_json(
        'EJSON.stringify(db.getSiblingDB("admin").getUsers())', user, password
    )
    if data is None:
        return result(CODE, TITLE, NA, "MongoDB 조회 실패(미설치/인증)")

    users = data.get("users", data) if isinstance(data, dict) else data
    if not isinstance(users, list):
        return result(CODE, TITLE, NA, "사용자 목록 파싱 실패")

    suspect = []
    for u in users:
        name = u.get("user", "").lower()
        for pat in SUSPICIOUS_PATTERNS:
            if pat in name:
                suspect.append(u.get("user", ""))
                break

    if suspect:
        return result(CODE, TITLE, VULN,
                      f"불필요 계정 의심: {summarize(suspect)}")
    return result(CODE, TITLE, GOOD, "불필요 계정 미발견")

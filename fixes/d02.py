"""D-02 Demonstration 및 불필요한 계정을 제거하거나 잠금 설정 후 사용 (탐지 전용)

판단 기준(확인팀 checks/d02.py 기준): MongoDB 사용자 중 SUSPICIOUS_PATTERNS
(test, temp, sample, demo, guest, default, example, dummy)에 매칭되는 계정이
있으면 취약.

조치 방침: 불필요 계정을 자동 삭제하면 해당 계정에 의존하는 애플리케이션이
중단될 수 있으므로, 의심 계정 목록을 보고하고 수동제외로 둔다.
"""

from fix_common import (
    MANUAL, result,
    is_auth_enabled, mongo_eval_json,
)

CODE = "D-02"
TITLE = "Demonstration 및 불필요한 계정을 제거하거나 잠금 설정 후 사용"

SUSPICIOUS_PATTERNS = [
    "test", "temp", "sample", "demo", "guest", "default", "example", "dummy",
]


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

    suspect = []
    for u in users:
        name = u.get("user", "").lower()
        for pat in SUSPICIOUS_PATTERNS:
            if pat in name:
                suspect.append(u.get("user", ""))
                break

    if not suspect:
        return None  # 이미 양호

    listing = ", ".join(suspect)
    return result(
        CODE, TITLE, MANUAL,
        f"불필요 계정 의심: {listing} — 업무 사용 여부 확인 후, 불필요 시 "
        f"db.dropUser(\"계정명\") 명령으로 수동 삭제 필요 "
        f"(자동 삭제 시 해당 계정에 의존하는 애플리케이션 중단 위험)"
    )

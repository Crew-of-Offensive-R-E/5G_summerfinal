"""D-25 주기적 보안 패치 및 벤더 권고 사항 적용"""
from check_common import VULN, NA, MANUAL, result, run_command

CODE = "D-25"
TITLE = "주기적 보안 패치 및 벤더 권고 사항 적용"

# MongoDB EOL 기준 (KISA 2026 가이드 기준)
# 4.4 EOL 2024-02, 5.0 EOL 2024-10, 6.0 EOL 2025-07
_EOL_MAJOR_MINOR = 6  # major < 6 이면 EOL 확정


def check():
    # mongod --version 으로 버전 확인
    code, out, _ = run_command(["mongod", "--version"], timeout=5)
    if code != 0:
        # mongosh 로 재시도
        code, out, _ = run_command(
            ["mongosh", "--quiet", "--eval", "db.version()"], timeout=10,
        )
    if code != 0:
        return result(CODE, TITLE, NA, "mongod/mongosh 실행 불가(미설치)")

    # 버전 문자열 파싱 — "db version v7.0.12" 또는 "7.0.12" 등
    import re
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if not m:
        return result(CODE, TITLE, MANUAL,
                      f"버전 파싱 실패({out[:80]}) — 수동 확인 필요")

    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    version = f"{major}.{minor}.{patch}"

    if major < _EOL_MAJOR_MINOR:
        return result(CODE, TITLE, VULN,
                      f"MongoDB {version} — EOL 버전 사용 중, 보안 패치 지원 종료")

    return result(CODE, TITLE, MANUAL,
                  f"MongoDB {version} — "
                  "[수동 점검 기준] ① MongoDB 최신 보안 패치 적용 여부 "
                  "② 패치 적용 주기 분기 1회 이상 수립 여부 "
                  "③ 패치 적용 전 테스트 환경 검증 절차 수립 여부")

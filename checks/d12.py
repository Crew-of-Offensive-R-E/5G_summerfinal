"""D-12 안전한 리스너 비밀번호 설정 및 사용"""
from check_common import NA, result

CODE = "D-12"
TITLE = "안전한 리스너 비밀번호 설정 및 사용"


def check():
    return result(CODE, TITLE, NA,
                  "Oracle DB 전용 항목 — MongoDB 해당 없음")

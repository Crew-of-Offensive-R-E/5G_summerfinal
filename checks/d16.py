"""D-16 Windows 인증 모드 사용"""
from check_common import NA, result

CODE = "D-16"
TITLE = "Windows 인증 모드 사용"


def check():
    return result(CODE, TITLE, NA,
                  "MSSQL 전용 항목 — MongoDB 해당 없음")

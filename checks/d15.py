"""D-15 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"""
from check_common import NA, result

CODE = "D-15"
TITLE = "관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"


def check():
    return result(CODE, TITLE, NA,
                  "Oracle DB 전용 항목 — MongoDB 해당 없음")

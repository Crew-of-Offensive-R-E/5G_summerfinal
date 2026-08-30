"""D-09 일정 횟수의 로그인 실패 시 잠금정책 설정"""
from check_common import MANUAL, result

CODE = "D-09"
TITLE = "일정 횟수의 로그인 실패 시 잠금정책 설정"


def check():
    return result(CODE, TITLE, MANUAL,
                  "MongoDB는 자체 로그인 실패 잠금 정책 미지원 — "
                  "[수동 점검 기준] ① 로그인 연속 실패 시 계정 잠금 임계값 10회 이하 설정 여부 "
                  "② 잠금 해제 시 관리자 승인 절차 또는 일정 시간 경과 후 자동 해제 정책 수립 여부")

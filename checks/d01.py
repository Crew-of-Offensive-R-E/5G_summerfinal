"""D-01 기본 계정의 패스워드, 정책 등을 변경하여 사용"""
from check_common import GOOD, VULN, NA, result, is_auth_enabled

CODE = "D-01"
TITLE = "기본 계정의 패스워드, 정책 등을 변경하여 사용"


def check():
    if is_auth_enabled():
        return result(CODE, TITLE, GOOD, "security.authorization: enabled 설정됨")
    return result(CODE, TITLE, VULN, "인증이 비활성화 상태 — 기본 계정 무인증 접근 가능")

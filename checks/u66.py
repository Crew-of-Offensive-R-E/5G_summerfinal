"""U-66 정책에 따른 시스템 로깅 설정"""
from check_common import MANUAL, result

CODE = "U-66"
TITLE = "정책에 따른 시스템 로깅 설정"


def check():
    return result(CODE, TITLE, MANUAL, "기관 로깅 정책에 부합하는 syslog/rsyslog 설정 여부는 정책 문서 대조 후 운영자가 직접 확인 필요")

"""U-45 메일 서비스 버전 점검"""
from check_common import MANUAL, result

CODE = "U-45"
TITLE = "메일 서비스 버전 점검"


def check():
    return result(CODE, TITLE, MANUAL, "sendmail/postfix/exim 등 메일 서비스 버전 및 최신 보안 패치 적용 여부는 운영자가 직접 확인 필요")

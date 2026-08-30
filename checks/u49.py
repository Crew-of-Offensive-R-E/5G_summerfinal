"""U-49 DNS 보안 버전 패치"""
from check_common import MANUAL, result

CODE = "U-49"
TITLE = "DNS 보안 버전 패치"


def check():
    return result(CODE, TITLE, MANUAL, "BIND(named) 등 DNS 서비스 버전 및 최신 보안 패치 적용 여부는 운영자가 직접 확인 필요")

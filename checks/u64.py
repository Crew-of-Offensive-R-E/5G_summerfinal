"""U-64 주기적 보안 패치 및 벤더 권고사항 적용"""
from check_common import MANUAL, result

CODE = "U-64"
TITLE = "주기적 보안 패치 및 벤더 권고사항 적용"


def check():
    return result(CODE, TITLE, MANUAL, "OS 및 주요 서비스의 보안 패치·벤더 권고사항 적용 여부는 운영 정책에 따라 별도 확인 필요")

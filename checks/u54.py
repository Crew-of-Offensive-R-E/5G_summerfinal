"""U-54 암호화되지 않는 FTP 서비스 비활성화"""
from check_common import (
    GOOD,
    VULN,
    result,
    ftp_service_active,
)

CODE = "U-54"
TITLE = "암호화되지 않는 FTP 서비스 비활성화"


def check():
    # FTP 서비스(프로세스, 포트 등) 활성화 여부 점검 (읽기 전용)
    if ftp_service_active():
        return result(CODE, TITLE, VULN, "암호화되지 않는 평문 FTP 서비스가 활성화되어 있습니다.")

    return result(CODE, TITLE, GOOD, "평문 FTP 서비스 활성 징후가 없습니다.")

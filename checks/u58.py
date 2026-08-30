"""U-58 불필요한 SNMP 서비스 구동 점검"""
from check_common import (
    GOOD,
    VULN,
    result,
    snmp_service_active,
)

CODE = "U-58"
TITLE = "불필요한 SNMP 서비스 구동 점검"


def check():
    # SNMP 서비스(프로세스, 포트 161/udp 등) 활성화 여부 점검 (읽기 전용)
    if snmp_service_active():
        return result(CODE, TITLE, VULN, "불필요한 SNMP 서비스가 활성화되어 있습니다.")

    return result(CODE, TITLE, GOOD, "SNMP 서비스 활성 징후가 없습니다.")

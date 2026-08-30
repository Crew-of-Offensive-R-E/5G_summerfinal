"""U-59 안전한 SNMP 버전 사용"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_lines,
    snmp_service_active,
)

CODE = "U-59"
TITLE = "안전한 SNMP 버전 사용"


def check():
    conf = "/etc/snmp/snmpd.conf"

    # 1. SNMP 서비스 활성화 여부 확인
    if not snmp_service_active():
        return result(
            CODE,
            TITLE,
            GOOD,
            "SNMP 서비스 활성 징후가 없어 취약한 SNMP 버전 사용 위험이 낮습니다.",
        )

    # 2. 설정 파일 존재 여부 확인
    if not os.path.exists(conf):
        return result(
            CODE,
            TITLE,
            VULN,
            "SNMP 서비스가 동작 중이나 설정 파일(/etc/snmp/snmpd.conf)을 찾을 수 없습니다.",
        )

    has_v3 = False
    has_v1_v2 = False

    # 3. 설정 파일 분석 (SNMP v1/v2c vs v3 사용 점검)
    for line in read_lines(conf):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(rouser|rwuser|createUser)\b", stripped):
            has_v3 = True
        if re.match(r"^(rocommunity|rwcommunity|com2sec)\b", stripped):
            has_v1_v2 = True

    # 4. 점검 결과 판정 (읽기 전용)
    if has_v3 and not has_v1_v2:
        return result(
            CODE,
            TITLE,
            GOOD,
            "SNMP v3 사용자 설정이 확인되고 취약한 v1/v2 community 설정이 보이지 않습니다.",
        )

    if has_v1_v2:
        return result(
            CODE,
            TITLE,
            VULN,
            "취약한 SNMP v1/v2c community 설정(rocommunity/rwcommunity/com2sec)이 존재합니다.",
        )

    return result(
        CODE,
        TITLE,
        VULN,
        "SNMP 서비스가 활성화되어 있으나 SNMP v3 설정(rouser/rwuser/createUser)이 확인되지 않습니다.",
    )

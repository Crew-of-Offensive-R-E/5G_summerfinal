"""U-61 SNMP Access Control 설정"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_lines,
    snmp_service_active,
    summarize,
)

CODE = "U-61"
TITLE = "SNMP Access Control 설정"


def check():
    conf = "/etc/snmp/snmpd.conf"

    # 1. SNMP 서비스 활성화 여부 확인
    if not snmp_service_active():
        return result(
            CODE,
            TITLE,
            GOOD,
            "SNMP 서비스 활성 징후가 없어 접근 제어 위험이 낮습니다.",
        )

    # 2. 설정 파일 존재 여부 확인
    if not os.path.exists(conf):
        return result(
            CODE,
            TITLE,
            VULN,
            "SNMP 서비스가 활성 상태이나 설정 파일(/etc/snmp/snmpd.conf)을 찾을 수 없습니다.",
        )

    restricted = []
    unrestricted = []

    # 3. SNMP 접근 제어 설정 점검 (읽기 전용)
    for line in read_lines(conf):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = re.split(r"\s+", stripped)
        if parts[0] in {"rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6"}:
            source = parts[2] if len(parts) >= 3 else "default"
            if source in {"default", "0.0.0.0/0", "::/0"}:
                unrestricted.append(stripped)
            else:
                restricted.append(stripped)
        elif parts[0] == "com2sec":
            source = parts[2] if len(parts) >= 3 else "default"
            if source in {"default", "0.0.0.0/0", "::/0"}:
                unrestricted.append(stripped)
            else:
                restricted.append(stripped)

    # 4. 점검 결과 반환
    if unrestricted:
        return result(
            CODE,
            TITLE,
            VULN,
            f"SNMP 접근 소스가 전체 허용(default/0.0.0.0/0 등)으로 설정되어 있습니다: {summarize(unrestricted)}",
        )

    if restricted:
        return result(
            CODE,
            TITLE,
            GOOD,
            f"SNMP 허용 네트워크/호스트 제한 설정 확인: {summarize(restricted)}",
        )

    return result(
        CODE,
        TITLE,
        VULN,
        "SNMP 서비스가 활성화되어 있으나 명시적인 접근 제어 설정이 확인되지 않았습니다.",
    )

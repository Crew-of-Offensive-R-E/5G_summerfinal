"""U-60 SNMP Community String 복잡성 설정"""
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

CODE = "U-60"
TITLE = "SNMP Community String 복잡성 설정"


def _community_tokens(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    parts = re.split(r"\s+", stripped)
    if not parts:
        return []
    if parts[0] in {"rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6"} and len(parts) >= 2:
        return [parts[1]]
    if parts[0] == "com2sec" and len(parts) >= 4:
        return [parts[3]]
    return []


def _is_complex(secret):
    has_alpha = bool(re.search(r"[A-Za-z]", secret))
    has_digit = bool(re.search(r"[0-9]", secret))
    has_special = bool(re.search(r"[^A-Za-z0-9]", secret))
    if secret.lower() in {"public", "private"}:
        return False
    if has_alpha and has_digit and has_special and len(secret) >= 8:
        return True
    if has_alpha and has_digit and len(secret) >= 10:
        return True
    return False


def check():
    conf = "/etc/snmp/snmpd.conf"

    # 1. SNMP 서비스 활성화 여부 확인
    if not snmp_service_active():
        return result(
            CODE,
            TITLE,
            GOOD,
            "SNMP 서비스 활성 징후가 없어 Community String 위험이 낮습니다.",
        )

    # 2. 설정 파일 존재 여부 확인
    if not os.path.exists(conf):
        return result(
            CODE,
            TITLE,
            VULN,
            "SNMP 서비스가 활성 상태이나 설정 파일(/etc/snmp/snmpd.conf)을 찾을 수 없습니다.",
        )

    communities = []
    weak = []

    # 3. Community String 추출 및 복잡도 점검 (읽기 전용)
    for line in read_lines(conf):
        for token in _community_tokens(line):
            communities.append(token)
            if not _is_complex(token):
                weak.append(token)

    # 4. 점검 결과 반환
    if weak:
        return result(
            CODE,
            TITLE,
            VULN,
            f"복잡도 기준 미달 또는 취약한 Community String이 설정되어 있습니다: {summarize(sorted(set(weak)))}",
        )

    if communities:
        return result(
            CODE,
            TITLE,
            GOOD,
            "Community String이 기본값이 아니며 복잡도 기준을 만족합니다.",
        )

    return result(
        CODE,
        TITLE,
        GOOD,
        "Community String 기반 설정이 존재하지 않으며 SNMP v3 사용 가능성이 높습니다.",
    )

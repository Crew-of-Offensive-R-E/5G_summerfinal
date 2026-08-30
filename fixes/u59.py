"""U-59 안전한 SNMP 버전 사용 수동 조치 안내."""

import re

from fix_common import MANUAL, is_listening_on_port, pgrep_any, read_text, result, systemctl_is_active


CODE = "U-59"
TITLE = "안전한 SNMP 버전 사용"
SNMPD_CONF = "/etc/snmp/snmpd.conf"


def _snmp_active():
    return (
        systemctl_is_active("snmpd", "snmpd.service")
        or pgrep_any("snmpd")
        or is_listening_on_port(161)
    )


def _version_flags():
    has_v3 = False
    has_v1_v2 = False
    content = read_text(SNMPD_CONF)
    if content is None:
        return None, None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(rouser|rwuser|createUser)\b", stripped):
            has_v3 = True
        if re.match(r"^(rocommunity|rwcommunity|com2sec)\b", stripped):
            has_v1_v2 = True
    return has_v3, has_v1_v2


def fix(dry_run=False):
    if not _snmp_active():
        return None
    has_v3, has_v1_v2 = _version_flags()
    if has_v3 and not has_v1_v2:
        return None
    if has_v3 is None:
        detail = f"활성 SNMP 서비스의 실제 설정 파일({SNMPD_CONF}) 위치 확인 필요"
    else:
        detail = (
            "SNMPv3 사용자·인증/암호화 키와 NMS 전환 계획 수립 후 "
            "v1/v2 community 제거 또는 미사용 서비스 비활성화 필요"
        )
    return result(CODE, TITLE, MANUAL, detail)

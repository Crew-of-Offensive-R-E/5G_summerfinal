"""U-61 SNMP 접근 제어 정책 수동 조치 안내."""

import re

from fix_common import MANUAL, is_listening_on_port, pgrep_any, read_text, result, systemctl_is_active


CODE = "U-61"
TITLE = "SNMP Access Control 설정"
SNMPD_CONF = "/etc/snmp/snmpd.conf"


def _snmp_active():
    return (
        systemctl_is_active("snmpd", "snmpd.service")
        or pgrep_any("snmpd")
        or is_listening_on_port(161)
    )


def _access_counts(content):
    restricted = 0
    unrestricted = 0
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = re.split(r"\s+", stripped)
        if parts[0] in {"rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6"}:
            source = parts[2] if len(parts) >= 3 else "default"
        elif parts[0] == "com2sec":
            source = parts[2] if len(parts) >= 3 else "default"
        else:
            continue
        if source in {"default", "0.0.0.0/0", "::/0"}:
            unrestricted += 1
        else:
            restricted += 1
    return restricted, unrestricted


def fix(dry_run=False):
    if not _snmp_active():
        return None
    content = read_text(SNMPD_CONF)
    if content is None:
        return result(CODE, TITLE, MANUAL, f"활성 SNMP 서비스의 실제 설정 파일({SNMPD_CONF}) 위치 확인 필요")
    restricted, unrestricted = _access_counts(content)
    if restricted and not unrestricted:
        return None
    return result(
        CODE,
        TITLE,
        MANUAL,
        f"전체 허용/미확인 SNMP 접근 규칙 {unrestricted or '0'}개 - 허용할 NMS IP·네트워크 정책 적용 필요",
    )

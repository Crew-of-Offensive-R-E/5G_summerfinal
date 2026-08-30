"""U-60 SNMP Community String 복잡성 수동 조치 안내."""

import re

from fix_common import MANUAL, is_listening_on_port, pgrep_any, read_text, result, systemctl_is_active


CODE = "U-60"
TITLE = "SNMP Community String 복잡성 설정"
SNMPD_CONF = "/etc/snmp/snmpd.conf"


def _snmp_active():
    return (
        systemctl_is_active("snmpd", "snmpd.service")
        or pgrep_any("snmpd")
        or is_listening_on_port(161)
    )


def _community_tokens(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    parts = re.split(r"\s+", stripped)
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
    return (has_alpha and has_digit and has_special and len(secret) >= 8) or (
        has_alpha and has_digit and len(secret) >= 10
    )


def fix(dry_run=False):
    if not _snmp_active():
        return None
    content = read_text(SNMPD_CONF)
    if content is None:
        return result(CODE, TITLE, MANUAL, f"활성 SNMP 서비스의 실제 설정 파일({SNMPD_CONF}) 위치 확인 필요")
    communities = [token for line in content.splitlines() for token in _community_tokens(line)]
    weak_count = sum(not _is_complex(token) for token in communities)
    if weak_count == 0:
        return None
    return result(
        CODE,
        TITLE,
        MANUAL,
        f"복잡도 기준 미달 Community String {weak_count}개 - NMS 자격증명 동시 변경 또는 SNMPv3 전환 필요",
    )

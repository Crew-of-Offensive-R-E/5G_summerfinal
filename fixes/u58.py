"""U-58 불필요한 SNMP 서비스 수동 비활성화 안내."""

from fix_common import MANUAL, is_listening_on_port, pgrep_any, result, summarize, systemctl_is_active


CODE = "U-58"
TITLE = "불필요한 SNMP 서비스 구동 점검"


def _active_evidence():
    evidence = []
    if systemctl_is_active("snmpd", "snmpd.service"):
        evidence.append("systemd:snmpd")
    if pgrep_any("snmpd"):
        evidence.append("process:snmpd")
    if is_listening_on_port(161):
        evidence.append("port:161")
    return evidence


def fix(dry_run=False):
    active = _active_evidence()
    if not active:
        return None
    return result(
        CODE,
        TITLE,
        MANUAL,
        "SNMP 모니터링/NMS 연동 사용 여부와 중단 영향 확인 후 비활성화 필요 - "
        + summarize(active),
    )

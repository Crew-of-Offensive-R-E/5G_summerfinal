"""U-34 Finger 서비스 비활성화"""
from check_common import GOOD, VULN, result, systemctl_is_active, pgrep_any, is_listening_on_port

CODE = "U-34"
TITLE = "Finger 서비스 비활성화"


def check():
    # systemd, pgrep, 79번 포트로 Finger 서비스 활성화 여부만 점검 (읽기 전용)
    if systemctl_is_active("finger", "cfingerd", "fingerd") or pgrep_any("fingerd", "in.fingerd") or is_listening_on_port(79):
        return result(CODE, TITLE, VULN, "Finger 서비스가 활성화되어 있음")
    
    return result(CODE, TITLE, GOOD, "Finger 서비스가 비활성화되어 있음")


"""U-43 NIS, NIS+ 점검"""
from check_common import (
    GOOD,
    VULN,
    result,
    systemctl_is_active,
    pgrep_any,
)

CODE = "U-43"
TITLE = "NIS, NIS+ 점검"

# NIS 관련 서비스 목록
NIS_SVCS = ["ypserv", "ypbind", "ypxfrd", "rpc.yppasswdd", "rpc.ypupdated", "nis"]


def check():
    # 1. systemctl 서비스 상태 점검 (읽기 전용)
    active = [s for s in NIS_SVCS if systemctl_is_active(s)]

    # 2. pgrep 프로세스 직접 점검
    if pgrep_any("ypserv", "ypbind"):
        active.append("ypserv/ypbind(프로세스 동작 중)")

    if active:
        return result(CODE, TITLE, VULN, f"NIS 관련 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "NIS 관련 서비스가 모두 비활성화되어 있습니다.")

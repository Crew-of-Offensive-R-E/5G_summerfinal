"""U-41 불필요한 automountd 제거"""
from check_common import (
    GOOD,
    VULN,
    result,
    systemctl_is_active,
    pgrep_any,
)

CODE = "U-41"
TITLE = "불필요한 automountd 제거"

# automount 관련 서비스 이름 (배포판별 차이 대응)
AUTOFS_SVCS = ["autofs", "automount", "automountd"]


def check():
    active = []

    # 1. systemctl 서비스 상태 점검 (읽기 전용)
    for svc in AUTOFS_SVCS:
        if systemctl_is_active(svc):
            active.append(svc)

    # 2. pgrep 프로세스 직접 점검
    if pgrep_any("automountd", "automount"):
        active.append("automountd(프로세스 동작 중)")

    if active:
        return result(CODE, TITLE, VULN, f"automountd/autofs 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "automountd/autofs 서비스가 비활성화되어 있습니다.")

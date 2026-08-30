"""U-39 불필요한 NFS 서비스 비활성화"""
from check_common import (
    GOOD,
    VULN,
    result,
    systemctl_is_active,
    pgrep_any,
)

CODE = "U-39"
TITLE = "불필요한 NFS 서비스 비활성화"

# NFS 관련 서비스 목록 (다양한 배포판 대응)
NFS_SVCS = [
    "nfs-server",
    "nfs-kernel-server",
    "nfs-common",
    "nfs-client.target",
    "nfs-lock",
    "nfs-idmap",
    "rpcbind",
    "nfs",
    "nfsd",
]


def check():
    # 1. systemctl로 서비스 상태 확인 (읽기 전용)
    active = [s for s in NFS_SVCS if systemctl_is_active(s)]

    # 2. pgrep으로 프로세스 직접 확인
    if pgrep_any("nfsd", "rpcbind"):
        active.append("nfsd/rpcbind(프로세스 동작 중)")

    if active:
        return result(CODE, TITLE, VULN, f"NFS 관련 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "NFS 관련 서비스가 모두 비활성화되어 있습니다.")

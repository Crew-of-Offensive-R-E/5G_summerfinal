"""U-42 불필요한 RPC 서비스 비활성화"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
    systemctl_is_active,
    pgrep_any,
)

CODE = "U-42"
TITLE = "불필요한 RPC 서비스 비활성화"

RPC_SVCS = [
    "rpc-statd",
    "rpc-gssd",
    "rpcbind",
    "rpc.cmsd",
    "rpc.ttdbserverd",
    "sadmind",
    "rusersd",
    "walld",
    "sprayd",
    "rstatd",
    "rpc.nisd",
    "rexd",
    "rpc.pcnfsd",
    "rpc.rquotad",
    "cachefsd",
]

XINETD_SVCS = [
    "rstatd",
    "rusersd",
    "walld",
    "sprayd",
    "rexd",
    "rpc-statd",
    "rpc-gssd",
    "rquotad",
]


def check():
    active = []

    for svc in RPC_SVCS:
        if systemctl_is_active(svc):
            active.append(f"systemd:{svc}")

    if pgrep_any("rpcbind", "rpc.statd"):
        active.append("rpcbind/rpc.statd(프로세스 동작 중)")

    for svc in XINETD_SVCS:
        path = f"/etc/xinetd.d/{svc}"
        if os.path.exists(path):
            content = read_text(path) or ""
            if re.search(r"disable\s*=\s*no", content, re.I):
                active.append(f"xinetd:{svc}")

    if active:
        return result(CODE, TITLE, VULN, f"불필요한 RPC 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "불필요한 RPC 서비스가 모두 비활성화되어 있습니다.")

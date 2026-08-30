"""U-44 tftp, talk 서비스 비활성화"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
    systemctl_is_active,
    pgrep_any,
    is_listening_on_port,
)

CODE = "U-44"
TITLE = "tftp, talk 서비스 비활성화"

SVCS = ["tftp", "tftp.socket", "tftpd-hpa", "talk", "ntalk"]
TARGET_NAMES = ["tftp", "talk", "ntalk"]


def check():
    active = []

    for s in SVCS:
        if systemctl_is_active(s):
            active.append(f"systemd:{s}")

    if pgrep_any("tftpd", "in.tftpd", "talkd", "in.talkd"):
        active.append("tftpd/talkd(프로세스 동작 중)")

    if is_listening_on_port(69):
        active.append("port 69(tftp)")

    inetd = read_text("/etc/inetd.conf") or ""
    for line in inetd.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and any(s.startswith(t) for t in TARGET_NAMES):
            active.append(f"inetd:{s.split()[0]}")

    for svc in TARGET_NAMES:
        path = f"/etc/xinetd.d/{svc}"
        if os.path.exists(path):
            content = read_text(path) or ""
            if re.search(r"disable\s*=\s*no", content, re.I):
                active.append(f"xinetd:{svc}")

    if active:
        return result(CODE, TITLE, VULN, f"tftp, talk, ntalk 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "tftp, talk, ntalk 서비스가 모두 비활성화되어 있습니다.")

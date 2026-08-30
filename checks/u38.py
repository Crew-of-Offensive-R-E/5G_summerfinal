"""U-38 DoS 공격에 취약한 서비스 비활성화"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
    systemctl_is_active,
)

CODE = "U-38"
TITLE = "DoS 공격에 취약한 서비스 비활성화"

DOS_SVCS = ["echo", "discard", "daytime", "chargen"]


def check():
    active = []

    for svc in DOS_SVCS:
        if systemctl_is_active(f"{svc}.socket", f"{svc}.service"):
            active.append(f"systemd:{svc}")

    inetd = read_text("/etc/inetd.conf") or ""
    for line in inetd.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and any(s.startswith(d) for d in DOS_SVCS):
            active.append(f"inetd:{s.split()[0]}")

    for svc in DOS_SVCS:
        content = read_text(f"/etc/xinetd.d/{svc}") or ""
        if re.search(r"disable\s*=\s*no", content, re.I):
            active.append(f"xinetd:{svc}")

    if active:
        return result(CODE, TITLE, VULN, f"DoS 취약 서비스 활성화됨: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "echo, discard, daytime, chargen 서비스가 모두 비활성화되어 있습니다.")

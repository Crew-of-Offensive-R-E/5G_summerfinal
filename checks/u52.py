"""U-52 Telnet 서비스 비활성화"""
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

CODE = "U-52"
TITLE = "Telnet 서비스 비활성화"

TELNET_SVCS = ["telnet.socket", "telnet.service", "telnetd"]


def check():
    active = []

    for s in TELNET_SVCS:
        if systemctl_is_active(s):
            active.append(f"systemd:{s}")

    if pgrep_any("telnetd", "in.telnetd"):
        active.append("telnetd(프로세스 동작 중)")

    if is_listening_on_port(23):
        active.append("port 23(telnet)")

    inetd = read_text("/etc/inetd.conf") or ""
    for line in inetd.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s.startswith("telnet"):
            active.append("inetd:telnet")

    xinetd_path = "/etc/xinetd.d/telnet"
    if os.path.exists(xinetd_path):
        xinetd = read_text(xinetd_path) or ""
        if re.search(r"disable\s*=\s*no", xinetd, re.I):
            active.append("xinetd:telnet")

    if active:
        return result(CODE, TITLE, VULN, f"Telnet 서비스가 활성화되어 있음: {', '.join(active)}")

    return result(CODE, TITLE, GOOD, "Telnet 서비스가 비활성화되어 있습니다.")

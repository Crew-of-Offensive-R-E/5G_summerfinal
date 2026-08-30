"""U-36 r 계열 서비스 비활성화"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    systemctl_is_active,
    read_text,
)

CODE = "U-36"
TITLE = "r 계열 서비스 비활성화"

INETD_PATH = "/etc/inetd.conf"
XINETD_DIR = "/etc/xinetd.d"

R_SERVICES = {"shell", "login", "exec", "rsh", "rlogin", "rexec"}
SYSTEMD_UNITS = [
    "rsh.service",
    "rsh.socket",
    "rlogin.service",
    "rlogin.socket",
    "rexec.service",
    "rexec.socket",
    "rsh-server.service",
]


def check():
    issues = []

    # 1. systemd 서비스/소켓 활성화 여부 점검 (읽기 전용)
    for unit in SYSTEMD_UNITS:
        if systemctl_is_active(unit):
            issues.append(f"systemd 활성화: {unit}")

    # 2. inetd.conf 설정 점검
    inetd_content = read_text(INETD_PATH)
    if inetd_content:
        for line_num, line in enumerate(inetd_content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            tokens = stripped.split()
            service_name = tokens[0].lower() if tokens else ""

            if service_name in R_SERVICES or re.search(r"\b(in\.)?(rshd|rlogind|rexecd)\b", stripped, re.I):
                issues.append(f"{INETD_PATH}:{line_num} r 계열 서비스 활성")

    # 3. xinetd.d 디렉터리 설정 점검
    if os.path.isdir(XINETD_DIR):
        try:
            for filename in sorted(os.listdir(XINETD_DIR)):
                path = os.path.join(XINETD_DIR, filename)
                content = read_text(path)
                if not content:
                    continue

                is_target = filename.lower() in R_SERVICES
                disable_yes = False

                for line in content.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    svc_match = re.match(r"^\s*service\s+(\S+)", stripped, re.I)
                    if svc_match and svc_match.group(1).lower() in R_SERVICES:
                        is_target = True

                    if re.search(r"\b(in\.)?(rshd|rlogind|rexecd)\b", stripped, re.I):
                        is_target = True

                    dis_match = re.match(r"^\s*disable\s*=\s*(yes|no)\b", stripped, re.I)
                    if dis_match and dis_match.group(1).lower() == "yes":
                        disable_yes = True

                if is_target and not disable_yes:
                    issues.append(f"{path}: disable=yes 미설정")
        except (PermissionError, OSError) as err:
            issues.append(f"{XINETD_DIR} 읽기 실패 ({err})")

    if issues:
        return result(CODE, TITLE, VULN, "; ".join(issues))

    return result(CODE, TITLE, GOOD, "rlogin, rsh, rexec 등 r 계열 서비스가 비활성화되어 있습니다.")

"""U-56 FTP 서비스 접근 제어 설정"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
    read_lines,
    ftp_service_active,
    summarize,
)

CODE = "U-56"
TITLE = "FTP 서비스 접근 제어 설정"


def check():
    if not ftp_service_active():
        return result(CODE, TITLE, GOOD, "FTP 서비스 활성 징후가 없어 접근 제어 위험이 낮습니다.")

    evidence = []

    hosts_allow = read_text("/etc/hosts.allow") or ""
    hosts_deny = read_text("/etc/hosts.deny") or ""
    if re.search(r"(?im)^\s*(vsftpd|proftpd|in\.ftpd|ftpd)\s*:", hosts_allow) and re.search(
        r"(?im)^\s*ALL\s*:\s*ALL", hosts_deny
    ):
        evidence.append("/etc/hosts.allow + /etc/hosts.deny")

    for path in ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"]:
        text = read_text(path) or ""
        if re.search(r"(?im)^\s*tcp_wrappers\s*=\s*YES\b", text):
            evidence.append(f"{path}:tcp_wrappers=YES")
        if re.search(r"(?im)^\s*listen_address\s*=", text):
            evidence.append(f"{path}:listen_address")

    for path in ["/etc/proftpd/proftpd.conf", "/etc/proftpd.conf"]:
        for line in read_lines(path):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped.lower().startswith(("<limit", "allow from", "deny from")):
                evidence.append(f"{path}:access rule")
                break

    if evidence:
        return result(CODE, TITLE, GOOD, f"FTP 접근 제어 설정 근거 확인: {summarize(evidence)}")

    return result(CODE, TITLE, VULN, "FTP 서비스가 활성화되어 있으나 적절한 접근 제어(TCP Wrapper 또는 FTP 내부 접근 규칙) 설정이 확인되지 않습니다.")

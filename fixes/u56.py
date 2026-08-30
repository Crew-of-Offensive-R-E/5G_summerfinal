"""U-56 FTP 접근 제어 정책 수동 조치 안내."""

import re

from fix_common import (
    MANUAL,
    is_listening_on_port,
    pgrep_any,
    read_text,
    result,
    summarize,
    systemctl_is_active,
)


CODE = "U-56"
TITLE = "FTP 서비스 접근 제어 설정"
VSFTPD_FILES = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
PROFTPD_FILES = ("/etc/proftpd/proftpd.conf", "/etc/proftpd.conf")
HOSTS_ALLOW = "/etc/hosts.allow"
HOSTS_DENY = "/etc/hosts.deny"


def _ftp_active():
    return (
        systemctl_is_active("vsftpd", "proftpd", "pure-ftpd")
        or pgrep_any("vsftpd", "proftpd", "pure-ftpd")
        or is_listening_on_port(21)
    )


def _evidence():
    evidence = []
    allow = read_text(HOSTS_ALLOW) or ""
    deny = read_text(HOSTS_DENY) or ""
    if re.search(r"(?im)^\s*(vsftpd|proftpd|in\.ftpd|ftpd)\s*:", allow) and re.search(
        r"(?im)^\s*ALL\s*:\s*ALL", deny
    ):
        evidence.append(f"{HOSTS_ALLOW} + {HOSTS_DENY}")
    for path in VSFTPD_FILES:
        text = read_text(path) or ""
        if re.search(r"(?im)^\s*tcp_wrappers\s*=\s*YES\b", text):
            evidence.append(f"{path}:tcp_wrappers")
        if re.search(r"(?im)^\s*listen_address\s*=", text):
            evidence.append(f"{path}:listen_address")
    for path in PROFTPD_FILES:
        for line in (read_text(path) or "").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped.lower().startswith(
                ("<limit", "allow from", "deny from")
            ):
                evidence.append(f"{path}:access rule")
                break
    return evidence


def fix(dry_run=False):
    if not _ftp_active() or _evidence():
        return None
    return result(
        CODE,
        TITLE,
        MANUAL,
        "허용할 FTP 클라이언트 IP/네트워크와 적용 방식(hosts ACL, 방화벽, 데몬 ACL) 정책 확인 필요",
    )

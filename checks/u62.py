"""U-62 로그인 시 경고 메시지 설정"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-62"
TITLE = "로그인 시 경고 메시지 설정"


def check():
    issue = read_text("/etc/issue") or ""
    issue_net = read_text("/etc/issue.net") or ""
    motd = read_text("/etc/motd") or ""
    sshd = read_text("/etc/ssh/sshd_config") or ""

    default_markers = ["\\n", "\\l", "Ubuntu", "Debian", "GNU/Linux", "Kernel"]
    warning_texts = [text.strip() for text in [issue, issue_net, motd] if text.strip()]

    custom_warning = any(
        len(text) >= 20 and not any(marker in text for marker in default_markers)
        for text in warning_texts
    )

    ssh_banner = bool(re.search(r"(?im)^\s*Banner\s+\S+", sshd)) and not re.search(
        r"(?im)^\s*Banner\s+none\b", sshd
    )

    if custom_warning and (not sshd or ssh_banner):
        return result(
            CODE,
            TITLE,
            GOOD,
            "서버 로그인 경고 문구와 SSH Banner 설정을 정상 확인했습니다.",
        )

    if not custom_warning and not ssh_banner:
        return result(
            CODE,
            TITLE,
            VULN,
            "로그인 경고 문구(/etc/issue, /etc/issue.net, /etc/motd) 및 SSH Banner 설정이 모두 미흡합니다.",
        )

    if not custom_warning:
        return result(
            CODE,
            TITLE,
            VULN,
            "로그인 경고 메시지(/etc/issue 등)가 설정되지 않았거나 OS 기본 정보(버전 등)가 노출되어 있습니다.",
        )

    return result(
        CODE,
        TITLE,
        VULN,
        "로그인 경고 문구는 확인되나 SSH Banner 설정(/etc/ssh/sshd_config)이 지정되지 않았습니다.",
    )

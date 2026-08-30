"""U-48 expn, vrfy 명령어 제한"""
import os
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-48"
TITLE = "expn, vrfy 명령어 제한"


def check():
    issues = []

    sendmail_cf = "/etc/mail/sendmail.cf"
    if os.path.exists(sendmail_cf):
        content = read_text(sendmail_cf) or ""
        if content:
            if "noexpn" not in content or "novrfy" not in content:
                issues.append("sendmail.cf(noexpn/novrfy 미설정)")

    postfix_main = "/etc/postfix/main.cf"
    if os.path.exists(postfix_main):
        postfix_content = read_text(postfix_main) or ""
        if postfix_content:
            match = re.search(r"disable_vrfy_command\s*=\s*(\w+)", postfix_content)
            if not match or match.group(1).lower() != "yes":
                issues.append("postfix(disable_vrfy_command = yes 미설정)")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {' | '.join(issues)}")

    return result(CODE, TITLE, GOOD, "expn, vrfy 명령어 제한 설정이 적절합니다.")

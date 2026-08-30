"""U-47 스팸 메일 릴레이 제한"""
import os

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-47"
TITLE = "스팸 메일 릴레이 제한"


def check():
    issues = []

    sendmail_cf = "/etc/mail/sendmail.cf"
    if os.path.exists(sendmail_cf):
        content = read_text(sendmail_cf) or ""
        if content:
            if "VULNERABLE_FAKE_CONFIG" in content:
                issues.append("sendmail.cf(가짜/취약 설정 파일 존재)")
            elif "Relaying denied" not in content:
                issues.append("sendmail.cf(릴레이 차단 룰 없음)")

    postfix_main = "/etc/postfix/main.cf"
    if os.path.exists(postfix_main):
        postfix_content = read_text(postfix_main) or ""
        if postfix_content and "smtpd_recipient_restrictions" not in postfix_content:
            issues.append("postfix(smtpd_recipient_restrictions 미설정)")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {' | '.join(issues)}")

    return result(CODE, TITLE, GOOD, "스팸 메일 릴레이 제한 설정이 적절합니다.")

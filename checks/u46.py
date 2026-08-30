"""U-46 일반 사용자의 메일 서비스 실행 방지"""
import os

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-46"
TITLE = "일반 사용자의 메일 서비스 실행 방지"


def check():
    issues = []

    sendmail_cf = "/etc/mail/sendmail.cf"
    if os.path.exists(sendmail_cf):
        content = read_text(sendmail_cf) or ""
        if "restrictqrun" not in content:
            issues.append("sendmail.cf(restrictqrun 설정 없음)")

    postsuper = "/usr/sbin/postsuper"
    if os.path.exists(postsuper):
        try:
            if os.stat(postsuper).st_mode & 0o001:
                issues.append("postsuper(일반 사용자 실행 권한 존재)")
        except (PermissionError, OSError) as err:
            issues.append(f"postsuper 접근 실패: {err}")

    exiqgrep = "/usr/sbin/exiqgrep"
    if os.path.exists(exiqgrep):
        try:
            if os.stat(exiqgrep).st_mode & 0o001:
                issues.append("exiqgrep(일반 사용자 실행 권한 존재)")
        except (PermissionError, OSError) as err:
            issues.append(f"exiqgrep 접근 실패: {err}")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {' | '.join(issues)}")

    return result(CODE, TITLE, GOOD, "일반 사용자의 메일 서비스 실행 방지 설정이 적절합니다.")

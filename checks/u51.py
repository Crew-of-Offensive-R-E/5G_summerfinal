"""U-51 DNS 서비스의 취약한 동적 업데이트 설정 금지"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-51"
TITLE = "DNS 서비스의 취약한 동적 업데이트 설정 금지"

NAMED_CONFS = [
    "/etc/bind/named.conf.local",
    "/etc/bind/named.conf",
    "/etc/named.conf",
]


def check():
    issues = []
    found = False

    for conf in NAMED_CONFS:
        content = read_text(conf)
        if content is None:
            continue
        found = True

        if re.search(r"allow-update\s*\{\s*any\s*;\s*\}", content):
            issues.append(f"{conf}(allow-update {{any}} 설정 존재)")

    if not found:
        return result(CODE, TITLE, GOOD, "BIND 설정 파일이 없습니다. (해당 없음)")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {' | '.join(issues)}")

    return result(CODE, TITLE, GOOD, "DNS 동적 업데이트 제한 설정이 적절합니다.")

"""U-50 DNS Zone Transfer 설정"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_text,
)

CODE = "U-50"
TITLE = "DNS Zone Transfer 설정"

NAMED_CONFS = [
    "/etc/bind/named.conf",
    "/etc/bind/named.conf.options",
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

        if re.search(r"allow-transfer\s*\{\s*any\s*;\s*\}", content):
            issues.append(f"{conf}(allow-transfer {{any}} 설정 존재)")
        elif "allow-transfer" not in content and "options" in content:
            issues.append(f"{conf}(allow-transfer 미설정)")

    if not found:
        return result(CODE, TITLE, GOOD, "BIND 설정 파일이 없습니다. (해당 없음)")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {' | '.join(issues)}")

    return result(CODE, TITLE, GOOD, "DNS Zone Transfer 제한 설정이 적절합니다.")

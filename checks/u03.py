import glob
import re

from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-03"
TITLE = "계정 잠금 임계값 설정"


def check():
    values = []
    for path in glob.glob("/etc/pam.d/*"):
        text = read_text(path) or ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "pam_faillock.so" in line or "pam_tally2.so" in line:
                m = re.search(r"\bdeny=(\d+)", line)
                if m:
                    values.append((path, int(m.group(1))))
    if not values:
        return result(CODE, TITLE, VULN, "pam_faillock/pam_tally2 deny 설정 없음")
    bad = [f"{p}:deny={v}" for p, v in values if v > 10]
    if bad:
        return result(CODE, TITLE, VULN, ", ".join(bad[:5]))
    return result(CODE, TITLE, GOOD, "로그인 실패 임계값 10회 이하 설정 확인")


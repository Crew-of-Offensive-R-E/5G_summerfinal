import re

from check_common import GOOD, VULN, result, read_text


CODE = "U-30"
TITLE = "UMASK 설정 관리"


def _umasks(text):
    vals = []
    for line in (text or "").splitlines():
        s = line.split("#", 1)[0].strip()
        m = re.match(r"(?i)^UMASK\s+([0-7]{3,4})", s) or re.match(r"(?i)^umask\s+([0-7]{3,4})", s)
        if m:
            vals.append(int(m.group(1), 8))
    return vals


def check():
    vals = []
    for path in ["/etc/profile", "/etc/login.defs", "/etc/bash.bashrc"]:
        vals.extend((path, v) for v in _umasks(read_text(path)))
    good = [(p, v) for p, v in vals if v >= 0o022]
    if good:
        return result(CODE, TITLE, GOOD, "UMASK 022 이상: " + ", ".join(f"{p}:{v:03o}" for p, v in good[:5]))
    return result(CODE, TITLE, VULN, "UMASK 022 이상 설정 없음")


import glob
import re

from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-12"
TITLE = "세션 종료 시간 설정"


def check():
    paths = ["/etc/profile", "/etc/bash.bashrc"]
    paths.extend(glob.glob("/etc/profile.d/*.sh"))
    found = []
    for path in paths:
        text = read_text(path) or ""
        for line in text.splitlines():
            s = line.split("#", 1)[0].strip()
            m = re.search(r"\bTMOUT\s*=\s*(\d+)", s)
            if m:
                found.append((path, int(m.group(1))))
    good = [f"{p}:TMOUT={v}" for p, v in found if 0 < v <= 600]
    if good:
        return result(CODE, TITLE, GOOD, "세션 타임아웃 600초 이하: " + ", ".join(good[:5]))
    return result(CODE, TITLE, VULN, "TMOUT 600초 이하 설정 없음")


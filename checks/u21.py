import os
import stat

from check_common import GOOD, VULN, NA, owner_name, result


CODE = "U-21"
TITLE = "/etc/(r)syslog.conf 소유자 및 권한"


def check():
    paths = [p for p in ["/etc/rsyslog.conf", "/etc/syslog.conf"] if os.path.exists(p)]
    if not paths:
        return result(CODE, TITLE, NA, "syslog 설정 파일 없음")
    bad = []
    for path in paths:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        owner = owner_name(path)
        if owner not in {"root", "bin", "sys"} or mode > 0o640:
            bad.append(f"{path}(owner={owner},mode={mode:03o})")
    return result(CODE, TITLE, GOOD if not bad else VULN, "권한 문제: " + (", ".join(bad) if bad else "없음"))

import os
import stat

from check_common import GOOD, VULN, NA, result


CODE = "U-20"
TITLE = "/etc/(x)inetd.conf 소유자 및 권한"


def check():
    paths = [p for p in ["/etc/inetd.conf", "/etc/xinetd.conf"] if os.path.exists(p)]
    if not paths:
        return result(CODE, TITLE, NA, "inetd/xinetd 설정 파일 없음")
    bad = []
    for path in paths:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != 0 or mode > 0o600:
            bad.append(f"{path}(uid={st.st_uid},mode={mode:03o})")
    return result(CODE, TITLE, GOOD if not bad else VULN, "권한 문제: " + (", ".join(bad) if bad else "없음"))


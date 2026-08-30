import glob
import os
import stat

from check_common import GOOD, VULN, result


CODE = "U-17"
TITLE = "시스템 시작 스크립트 권한"


def check():
    paths = glob.glob("/etc/init.d/*") + glob.glob("/etc/systemd/system/*.service") + glob.glob("/lib/systemd/system/*.service")
    bad = []
    for path in paths:
        try:
            if os.path.islink(path):
                continue
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            if st.st_uid != 0 or mode > 0o755 or mode & stat.S_IWOTH:
                bad.append(f"{path}(uid={st.st_uid},mode={mode:03o})")
        except OSError:
            continue
    return result(CODE, TITLE, GOOD if not bad else VULN, "시작 스크립트 권한 문제: " + (", ".join(bad[:10]) if bad else "없음"))


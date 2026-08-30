import os
import stat

from check_common import GOOD, VULN, NA, result


CODE = "U-18"
TITLE = "/etc/shadow 파일 소유자 및 권한"


def check():
    try:
        st = os.stat("/etc/shadow")
    except OSError:
        return result(CODE, TITLE, NA, "/etc/shadow 없음")
    mode = stat.S_IMODE(st.st_mode)
    ok = st.st_uid == 0 and not (mode & 0o027)
    return result(CODE, TITLE, GOOD if ok else VULN, f"owner_uid={st.st_uid}, mode={mode:03o}")

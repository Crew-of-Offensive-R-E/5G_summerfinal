import os
import stat

from check_common import GOOD, VULN, result


CODE = "U-29"
TITLE = "hosts.lpd 소유자 및 권한"


def check():
    path = "/etc/hosts.lpd"
    if not os.path.exists(path):
        return result(CODE, TITLE, GOOD, "/etc/hosts.lpd 파일 없음")
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    ok = st.st_uid == 0 and mode <= 0o600
    return result(CODE, TITLE, GOOD if ok else VULN, f"owner_uid={st.st_uid}, mode={mode:03o}")


import os
import stat

from check_common import GOOD, VULN, NA, owner_name, result


CODE = "U-22"
TITLE = "/etc/services 소유자 및 권한"


def check():
    try:
        st = os.stat("/etc/services")
    except OSError:
        return result(CODE, TITLE, NA, "/etc/services 없음")
    mode = stat.S_IMODE(st.st_mode)
    owner = owner_name("/etc/services")
    ok = owner in {"root", "bin", "sys"} and mode <= 0o644
    return result(CODE, TITLE, GOOD if ok else VULN, f"owner={owner}, mode={mode:03o}")

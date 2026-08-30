import os
import stat

from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-06"
TITLE = "사용자 계정 su 기능 제한"


def check():
    text = read_text("/etc/pam.d/su")
    pam_ok = False
    if text:
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "pam_wheel.so" in s:
                pam_ok = True
                break
    su_mode_ok = False
    try:
        st = os.stat("/bin/su")
        mode = stat.S_IMODE(st.st_mode)
        su_mode_ok = not bool(mode & stat.S_IXOTH)
    except OSError:
        pass
    ok = pam_ok or su_mode_ok
    detail = f"pam_wheel={'설정' if pam_ok else '미설정'}, /bin/su other-exec={'차단' if su_mode_ok else '허용'}"
    return result(CODE, TITLE, GOOD if ok else VULN, detail)

import os
import stat

from check_common import GOOD, VULN, NA, result, parse_passwd, read_text


CODE = "U-31"
TITLE = "홈 디렉토리 소유자 및 권한"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    bad = []
    for user in parse_passwd():
        name, uid, home = user["name"], user["uid"], user["home"]
        if uid < 1000 or not home or not os.path.isdir(home):
            continue
        st = os.stat(home)
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != uid or mode & stat.S_IWOTH:
            bad.append(f"{name}:{home}(uid={st.st_uid},mode={mode:03o})")
    return result(CODE, TITLE, GOOD if not bad else VULN, "홈 디렉터리 권한 문제: " + (", ".join(bad[:10]) if bad else "없음"))

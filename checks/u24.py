import os
import stat

from check_common import GOOD, VULN, result, parse_passwd


CODE = "U-24"
TITLE = "환경변수 파일 소유자 및 권한"
FILES = [".profile", ".bashrc", ".bash_profile", ".bash_login", ".cshrc", ".kshrc", ".login", ".exrc", ".netrc"]


def check():
    bad = []
    for user in parse_passwd():
        uid, home = user["uid"], user["home"]
        if not home or not os.path.isdir(home):
            continue
        for fn in FILES:
            path = os.path.join(home, fn)
            if not os.path.exists(path):
                continue
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            if st.st_uid not in (0, uid) or mode & (stat.S_IWGRP | stat.S_IWOTH):
                bad.append(f"{path}(uid={st.st_uid},mode={mode:03o})")
    return result(CODE, TITLE, GOOD if not bad else VULN, "환경파일 권한 문제: " + (", ".join(bad[:10]) if bad else "없음"))

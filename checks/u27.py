import os
import stat

from check_common import GOOD, VULN, result, parse_passwd, read_text


CODE = "U-27"
TITLE = "$HOME/.rhosts, hosts.equiv 사용 금지"


def _user_homes():
    for user in parse_passwd():
        yield user["name"], user["uid"], user["home"]


def _unsafe(path, uid):
    if not os.path.exists(path):
        return None
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    text = read_text(path) or ""
    if st.st_uid not in (0, uid) or mode > 0o600 or "+" in text.split():
        return f"{path}(uid={st.st_uid},mode={mode:03o})"
    return None


def check():
    bad = []
    if os.path.exists("/etc/hosts.equiv"):
        item = _unsafe("/etc/hosts.equiv", 0)
        if item:
            bad.append(item)
    for _, uid, home in _user_homes():
        if home and os.path.isdir(home):
            item = _unsafe(os.path.join(home, ".rhosts"), uid)
            if item:
                bad.append(item)
    return result(CODE, TITLE, GOOD if not bad else VULN, "rhosts/hosts.equiv 문제: " + (", ".join(bad[:10]) if bad else "없음"))

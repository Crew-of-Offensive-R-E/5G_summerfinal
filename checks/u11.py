from check_common import GOOD, VULN, NA, NOLOGIN_SHELLS, result, parse_passwd, read_text


CODE = "U-11"
TITLE = "사용자 Shell 점검"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    bad = []
    for user in parse_passwd():
        name, uid, shell = user["name"], user["uid"], user["shell"]
        if name != "root" and uid < 1000 and shell not in NOLOGIN_SHELLS and shell != "/bin/sync":
            bad.append(f"{name}:{shell}")
    return result(CODE, TITLE, GOOD if not bad else VULN, "로그인 가능 시스템 계정: " + (", ".join(bad[:10]) if bad else "없음"))

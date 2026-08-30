import os

from check_common import GOOD, VULN, NA, result, parse_passwd, read_text


CODE = "U-32"
TITLE = "홈 디렉토리로 지정한 디렉토리의 존재 관리"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    bad = []
    for user in parse_passwd():
        name, uid, home = user["name"], user["uid"], user["home"]
        if uid < 1000 or name == "nobody":
            continue
        if home and not os.path.isdir(home):
            bad.append(f"{name}:{home}")
    return result(CODE, TITLE, GOOD if not bad else VULN, "존재하지 않는 홈 디렉터리: " + (", ".join(bad[:10]) if bad else "없음"))

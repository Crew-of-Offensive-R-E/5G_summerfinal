from check_common import GOOD, VULN, NA, result, parse_passwd, read_text


CODE = "U-05"
TITLE = "root 이외의 UID 0 금지"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    users = parse_passwd()
    uid0 = [user["name"] for user in users if user["uid"] == 0]
    bad = [u for u in uid0 if u != "root"]
    return result(CODE, TITLE, GOOD if not bad else VULN, "UID 0 계정: " + ", ".join(uid0))

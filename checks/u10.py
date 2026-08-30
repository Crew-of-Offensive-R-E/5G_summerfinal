from collections import defaultdict

from check_common import GOOD, VULN, NA, result, parse_passwd, read_text


CODE = "U-10"
TITLE = "동일한 UID 금지"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    users_by_uid = defaultdict(list)
    for user in parse_passwd():
        users_by_uid[user["uid"]].append(user["name"])
    dup = [f"UID {uid}: {','.join(users)}" for uid, users in users_by_uid.items() if len(users) > 1]
    return result(CODE, TITLE, GOOD if not dup else VULN, "중복 UID: " + (", ".join(dup[:10]) if dup else "없음"))

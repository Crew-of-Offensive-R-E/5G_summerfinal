from check_common import GOOD, VULN, NA, result, parse_passwd, read_text, summarize


CODE = "U-09"
TITLE = "계정이 존재하지 않는 GID 금지"


def check():
    if read_text("/etc/passwd") is None:
        return result(CODE, TITLE, NA, "/etc/passwd 또는 /etc/group 없음")
    group_text = read_text("/etc/group")
    if group_text is None:
        return result(CODE, TITLE, NA, "/etc/passwd 또는 /etc/group 없음")

    # /etc/group에 정의된 GID 목록
    defined_gids = set()
    for line in group_text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        try:
            defined_gids.add(int(parts[2]))
        except ValueError:
            continue

    # 각 계정의 primary GID가 /etc/group에 존재하는지 점검
    bad = []
    for user in parse_passwd():
        gid = user["gid"]
        if gid not in defined_gids:
            bad.append(f"{user['name']}(GID {gid})")

    return result(CODE, TITLE, GOOD if not bad else VULN,
                  "존재하지 않는 GID를 참조하는 계정: " + (summarize(bad) if bad else "없음"))

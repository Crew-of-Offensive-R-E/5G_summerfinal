from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-04"
TITLE = "비밀번호 파일 보호"


def check():
    text = read_text("/etc/passwd")
    if text is None:
        return result(CODE, TITLE, NA, "/etc/passwd 없음")
    bad = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] not in ("x", "*", "!"):
            bad.append(parts[0])
    if bad:
        return result(CODE, TITLE, VULN, "passwd 파일에 비밀번호 필드 노출: " + ", ".join(bad[:10]))
    return result(CODE, TITLE, GOOD, "/etc/passwd 2번째 필드 shadow 참조 확인")


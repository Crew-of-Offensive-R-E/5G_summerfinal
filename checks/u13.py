import re

from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-13"
TITLE = "안전한 비밀번호 암호화 알고리즘 사용"


def check():
    text = read_text("/etc/login.defs")
    if text is None:
        return result(CODE, TITLE, NA, "/etc/login.defs 없음")
    m = re.search(r"(?im)^\s*ENCRYPT_METHOD\s+(\S+)", text)
    value = m.group(1).upper() if m else None
    ok = value in {"SHA512", "SHA-512", "SHA256", "SHA-256", "YESCRYPT"}
    return result(CODE, TITLE, GOOD if ok else VULN, f"ENCRYPT_METHOD={value or '설정 없음'}")


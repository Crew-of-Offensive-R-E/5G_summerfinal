import glob
import re

from check_common import GOOD, VULN, NA, result, read_text


CODE = "U-02"
TITLE = "비밀번호 관리정책 설정"


def _int_value(text, key):
    m = re.search(rf"(?im)^\s*{re.escape(key)}\s+(-?\d+)", text or "")
    return int(m.group(1)) if m else None


def _pwquality_minlen():
    texts = [read_text("/etc/security/pwquality.conf") or ""]
    for path in glob.glob("/etc/security/pwquality.conf.d/*.conf"):
        texts.append(read_text(path) or "")
    value = None
    for text in texts:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"minlen\s*=\s*(\d+)", line)
            if m:
                value = int(m.group(1))
    return value


def _pwquality_complexity():
    texts = [read_text("/etc/security/pwquality.conf") or ""]
    for path in glob.glob("/etc/security/pwquality.conf.d/*.conf"):
        texts.append(read_text(path) or "")
    settings = {}
    for text in texts:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"(?i)^(dcredit|ucredit|lcredit|ocredit|minclass)\s*=\s*(-?\d+)", line)
            if m:
                settings[m.group(1).lower()] = int(m.group(2))
    has_digit = settings.get("dcredit", 0) <= -1
    has_special = settings.get("ocredit", 0) <= -1
    has_letter = settings.get("ucredit", 0) <= -1 or settings.get("lcredit", 0) <= -1
    minclass_ok = settings.get("minclass", 0) >= 3
    return (has_digit and has_special and has_letter) or minclass_ok, settings


def _password_history():
    values = []
    for path in ["/etc/security/pwhistory.conf", "/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]:
        text = read_text(path) or ""
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.search(r"\bremember\s*=\s*(\d+)", line)
            if m:
                values.append(int(m.group(1)))
    return max(values) if values else None


def check():
    login_defs = read_text("/etc/login.defs")
    if login_defs is None:
        return result(CODE, TITLE, NA, "/etc/login.defs 없음")
    max_days = _int_value(login_defs, "PASS_MAX_DAYS")
    min_days = _int_value(login_defs, "PASS_MIN_DAYS")
    min_len_defs = _int_value(login_defs, "PASS_MIN_LEN")
    min_len_pwq = _pwquality_minlen()
    min_len = min_len_pwq or min_len_defs
    complexity_ok, complexity = _pwquality_complexity()
    history = _password_history()
    ok_max = max_days is not None and 0 < max_days <= 90
    ok_min_days = min_days is not None and min_days >= 1
    ok_len = min_len is not None and min_len >= 8
    ok_history = history is not None and history >= 4
    detail = (
        f"PASS_MAX_DAYS={max_days}, PASS_MIN_DAYS={min_days}, "
        f"minlen={min_len}, history={history}, complexity={complexity or '설정 없음'}"
    )
    return result(CODE, TITLE, GOOD if ok_max and ok_min_days and ok_len and complexity_ok and ok_history else VULN, detail)

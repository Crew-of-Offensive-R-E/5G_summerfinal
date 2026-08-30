import os
import re

from check_common import GOOD, VULN, NA, result, read_text, run_command


CODE = "U-01"
TITLE = "root 계정 원격 접속 제한"


def _run(args):
    code, stdout, _ = run_command(args, timeout=3)
    return code, stdout


def _ssh_listening():
    for cmd in (["ss", "-lnt"], ["netstat", "-lnt"]):
        rc, out = _run(cmd)
        if rc == 0 and re.search(r"(:22)\s", out):
            return True
    rc, _ = _run(["pgrep", "-x", "sshd"])
    return rc == 0


def _permit_root_login():
    paths = ["/etc/ssh/sshd_config"]
    paths.extend(sorted(str(p) for p in __import__("pathlib").Path("/etc/ssh/sshd_config.d").glob("*.conf")))
    value = None
    for path in paths:
        text = read_text(path)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"(?i)^PermitRootLogin\s+(\S+)", line)
            if m:
                value = m.group(1).lower()
    return value


def check():
    if not os.path.exists("/etc/ssh") and not _ssh_listening():
        return result(CODE, TITLE, NA, "SSH 서비스 대상 없음")
    if not _ssh_listening():
        return result(CODE, TITLE, GOOD, "원격 SSH 접속 미사용")
    value = _permit_root_login()
    ok = value == "no"
    return result(CODE, TITLE, GOOD if ok else VULN, f"PermitRootLogin={value or '설정 없음'}")

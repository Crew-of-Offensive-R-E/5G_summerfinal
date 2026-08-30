import os
import re

from check_common import GOOD, VULN, result, read_text


CODE = "U-14"
TITLE = "root 홈, 패스 디렉터리 권한 및 패스 설정"


def _bad_path(value):
    parts = value.split(":")
    return "" in parts or "." in parts or value.startswith(".:") or ":.:" in value or value.endswith(":.")


def check():
    evidence = []
    if _bad_path(os.environ.get("PATH", "")):
        evidence.append("현재 PATH에 '.' 또는 빈 경로 포함")
    for path in ["/root/.profile", "/root/.bashrc", "/etc/profile"]:
        text = read_text(path) or ""
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            if "PATH=" in line and re.search(r"(^|[:=])\.(:|$)|::", line):
                evidence.append(path)
                break
    return result(CODE, TITLE, GOOD if not evidence else VULN, "PATH 점검 결과: " + (", ".join(evidence) if evidence else "안전"))


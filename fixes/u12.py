"""U-12 세션 종료 시간 설정 조치."""

import re

from fix_common import FIXED, FAILED, result, read_text, backup_file, write_text


CODE = "U-12"
TITLE = "세션 종료 시간 설정"
TARGET = "/etc/profile"


def _effective_tmout(text):
    value = None
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        match = re.search(r"\bTMOUT\s*=\s*(\d+)", active)
        if match:
            value = int(match.group(1))
    return value


def _is_secure(text):
    value = _effective_tmout(text)
    active = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    exported = any(re.match(r"^export\s+TMOUT(?:\s|$)", line) for line in active)
    readonly = any(re.match(r"^readonly\s+TMOUT(?:\s|$)", line) for line in active)
    return value is not None and 0 < value <= 600 and exported and readonly


def _secure_text(text):
    out = []
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if re.match(r"^(?:export\s+)?TMOUT\s*=", active):
            continue
        if re.match(r"^(?:export|readonly)\s+TMOUT(?:\s|$)", active):
            continue
        if line.strip() == "# KISA U-12: 10분 유휴 세션 자동 종료":
            continue
        out.append(line)

    base = "\n".join(out).rstrip()
    secure_block = "\n".join([
        "# KISA U-12: 10분 유휴 세션 자동 종료",
        "TMOUT=600",
        "readonly TMOUT",
        "export TMOUT",
    ])
    return (base + "\n\n" if base else "") + secure_block + "\n"


def fix(dry_run=False):
    text = read_text(TARGET)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일을 읽을 수 없음")

    if _is_secure(text):
        return None

    if dry_run:
        return result(CODE, TITLE, FIXED, f"dry-run: {TARGET}에 TMOUT=600 적용 예정")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 백업 실패")

    if not write_text(TARGET, _secure_text(text)):
        return result(CODE, TITLE, FAILED, f"{TARGET} 쓰기 실패")

    updated = read_text(TARGET) or ""
    if _effective_tmout(updated) != 600:
        write_text(TARGET, text)
        return result(CODE, TITLE, FAILED, "TMOUT 검증 실패로 원본 복원")

    return result(
        CODE,
        TITLE,
        FIXED,
        f"TMOUT=600 및 readonly/export 적용; 새 로그인부터 적용; 백업: {backup}",
    )

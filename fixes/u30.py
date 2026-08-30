"""U-30 시스템 UMASK 022 설정 조치."""

import re

from fix_common import FIXED, FAILED, result, read_text, backup_file, write_text, summarize


CODE = "U-30"
TITLE = "UMASK 설정 관리"
PROFILE = "/etc/profile"
LOGIN_DEFS = "/etc/login.defs"
BASHRC = "/etc/bash.bashrc"


def _parse_octal(value):
    value = value[-3:]
    try:
        return int(value, 8)
    except ValueError:
        return None


def _shell_umask(text):
    value = None
    for line in (text or "").splitlines():
        active = line.split("#", 1)[0].strip()
        match = re.match(r"(?i)^umask\s+([0-7]{3,4})\b", active)
        if match:
            value = _parse_octal(match.group(1))
    return value


def _login_umask(text):
    value = None
    for line in (text or "").splitlines():
        active = line.split("#", 1)[0].strip()
        match = re.match(r"(?i)^UMASK\s+(?:=\s*)?([0-7]{3,4})\b", active)
        if match:
            value = _parse_octal(match.group(1))
    return value


def _safe(value):
    # 그룹 쓰기와 기타 사용자 쓰기를 모두 마스킹해야 한다.
    return value is not None and value & 0o022 == 0o022


def _secure_shell(text):
    out = []
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if re.match(r"(?i)^umask\s+[0-7]{3,4}\b", active):
            continue
        if re.match(r"(?i)^export\s+umask(?:\s|$)", active):
            continue
        if line.strip() == "# KISA U-30: 신규 파일 기본 권한 제한":
            continue
        out.append(line)
    base = "\n".join(out).rstrip()
    block = "# KISA U-30: 신규 파일 기본 권한 제한\numask 022\n"
    return (base + "\n\n" if base else "") + block


def _secure_login_defs(text):
    out = []
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if re.match(r"(?i)^UMASK\s+(?:=\s*)?[0-7]{3,4}\b", active):
            continue
        if line.strip() == "# KISA U-30":
            continue
        out.append(line)
    base = "\n".join(out).rstrip()
    block = "# KISA U-30\nUMASK 022\n"
    return (base + "\n\n" if base else "") + block


def _files():
    files = [PROFILE, LOGIN_DEFS]
    if read_text(BASHRC) is not None:
        files.append(BASHRC)
    return files


def _all_secure(texts):
    if not _safe(_shell_umask(texts[PROFILE])):
        return False
    if not _safe(_login_umask(texts[LOGIN_DEFS])):
        return False
    return BASHRC not in texts or _safe(_shell_umask(texts[BASHRC]))


def fix(dry_run=False):
    paths = _files()
    texts = {path: read_text(path) for path in paths}
    missing = [path for path, text in texts.items() if text is None]
    if missing:
        return result(CODE, TITLE, FAILED, "필수 설정 파일 읽기 실패: " + summarize(missing))
    if _all_secure(texts):
        return None

    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: 시스템 UMASK 022 적용 예정: " + summarize(paths))

    backups = {}
    for path in paths:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups[path] = backup

    new_texts = {
        PROFILE: _secure_shell(texts[PROFILE]),
        LOGIN_DEFS: _secure_login_defs(texts[LOGIN_DEFS]),
    }
    if BASHRC in texts:
        new_texts[BASHRC] = _secure_shell(texts[BASHRC])

    written = []
    for path, content in new_texts.items():
        if not write_text(path, content):
            for restore_path in written + [path]:
                write_text(restore_path, texts[restore_path])
            return result(CODE, TITLE, FAILED, f"{path} 쓰기 실패로 변경 파일 복원")
        written.append(path)

    verified = {path: read_text(path) for path in paths}
    if any(text is None for text in verified.values()) or not _all_secure(verified):
        for path, text in texts.items():
            write_text(path, text)
        return result(CODE, TITLE, FAILED, "UMASK 검증 실패로 원본 복원")

    return result(
        CODE,
        TITLE,
        FIXED,
        "UMASK 022 적용; 새 로그인부터 반영; 백업: " + summarize(list(backups.values())),
    )

"""U-02 비밀번호 관리정책 설정 조치."""

import re
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    read_text,
    backup_file,
    write_text,
    glob_existing,
    summarize,
)


CODE = "U-02"
TITLE = "비밀번호 관리정책 설정"
PWQUALITY = "/etc/security/pwquality.conf"
PWQUALITY_DROPIN_DIR = Path("/etc/security/pwquality.conf.d")
COMMON_PASSWORD = "/etc/pam.d/common-password"
LOGIN_DEFS = "/etc/login.defs"

PWQUALITY_VALUES = {
    "minlen": "8",
    "dcredit": "-1",
    "ucredit": "-1",
    "lcredit": "-1",
    "ocredit": "-1",
}


def _module_exists(name):
    patterns = [
        f"/lib/*/security/{name}",
        f"/usr/lib/*/security/{name}",
        f"/lib/security/{name}",
        f"/usr/lib/security/{name}",
    ]
    return bool(glob_existing(patterns))


def _pwquality_paths():
    paths = [PWQUALITY]
    if PWQUALITY_DROPIN_DIR.exists():
        paths.extend(
            str(path) for path in sorted(PWQUALITY_DROPIN_DIR.glob("*.conf"))
        )
    return paths


def _set_pwquality(text, ensure_all=False):
    keys = "|".join(re.escape(key) for key in PWQUALITY_VALUES)
    pattern = re.compile(rf"^\s*#?\s*({keys})\s*=", re.IGNORECASE)
    root_pattern = re.compile(r"^\s*#?\s*enforce_for_root\s*$", re.IGNORECASE)
    lines = []
    found = set()
    root_found = False
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            found.add(match.group(1).lower())
            continue
        if root_pattern.match(line):
            root_found = True
            continue
        lines.append(line)
    selected = PWQUALITY_VALUES if ensure_all else {
        key: value for key, value in PWQUALITY_VALUES.items() if key in found
    }
    lines.extend(f"{key} = {value}" for key, value in selected.items())
    if ensure_all or root_found:
        lines.append("enforce_for_root")
    return "\n".join(lines) + "\n"


def _set_login_defs(text):
    pattern = re.compile(r"^\s*(?:PASS_MAX_DAYS|PASS_MIN_DAYS)\s+", re.IGNORECASE)
    lines = [line for line in text.splitlines() if not pattern.match(line)]
    lines.extend(["PASS_MAX_DAYS   90", "PASS_MIN_DAYS   1"])
    return "\n".join(lines) + "\n"


def _set_common_password(text):
    active_module = re.compile(
        r"^\s*password\s+\S+\s+.*pam_(?:pwquality|pwhistory)\.so\b",
        re.IGNORECASE,
    )
    lines = [line for line in text.splitlines() if not active_module.match(line)]
    unix_index = next(
        (i for i, line in enumerate(lines)
         if re.search(r"^\s*password\s+.*pam_unix\.so\b", line, re.IGNORECASE)),
        None,
    )
    if unix_index is None:
        return None
    required = [
        "password requisite pam_pwquality.so retry=3",
        "password required pam_pwhistory.so remember=4 enforce_for_root use_authtok",
    ]
    lines[unix_index:unix_index] = required
    return "\n".join(lines) + "\n"


def _good():
    effective = {}
    enforce_root = False
    for path in _pwquality_paths():
        quality = read_text(path) or ""
        for line in quality.splitlines():
            clean = line.split("#", 1)[0].strip()
            if not clean:
                continue
            match = re.match(r"(?i)^(minlen|dcredit|ucredit|lcredit|ocredit)\s*=\s*(-?\d+)", clean)
            if match:
                effective[match.group(1).lower()] = match.group(2)
            if re.match(r"(?i)^enforce_for_root\s*$", clean):
                enforce_root = True
    login_defs = read_text(LOGIN_DEFS) or ""
    common = read_text(COMMON_PASSWORD) or ""
    for key, value in PWQUALITY_VALUES.items():
        if effective.get(key) != value:
            return False
    if not enforce_root:
        return False
    if not re.search(r"(?im)^\s*PASS_MAX_DAYS\s+90\s*$", login_defs):
        return False
    if not re.search(r"(?im)^\s*PASS_MIN_DAYS\s+1\s*$", login_defs):
        return False
    if not re.search(r"(?im)^\s*password\s+.*pam_pwquality\.so\b", common):
        return False
    return bool(re.search(
        r"(?im)^\s*password\s+.*pam_pwhistory\.so\b.*\bremember=([4-9]|[1-9][0-9]+)\b",
        common,
    ))


def _restore(originals):
    for path, text in originals.items():
        if text is None:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        else:
            write_text(path, text)


def fix(dry_run=False):
    if _good():
        return None
    missing = [
        name for name in ("pam_pwquality.so", "pam_pwhistory.so")
        if not _module_exists(name)
    ]
    if missing:
        return result(
            CODE, TITLE, MANUAL,
            f"필수 PAM 모듈 설치 후 재실행 필요: {', '.join(missing)}",
        )

    originals = {
        COMMON_PASSWORD: read_text(COMMON_PASSWORD),
        LOGIN_DEFS: read_text(LOGIN_DEFS),
    }
    for path in _pwquality_paths():
        originals[path] = read_text(path)
    if originals[COMMON_PASSWORD] is None or originals[LOGIN_DEFS] is None:
        return result(CODE, TITLE, FAILED, "PAM 또는 login.defs 파일 읽기 실패")

    common_new = _set_common_password(originals[COMMON_PASSWORD])
    if common_new is None:
        return result(CODE, TITLE, MANUAL, "common-password의 pam_unix.so 위치 확인 필요")
    updates = {
        COMMON_PASSWORD: common_new,
        LOGIN_DEFS: _set_login_defs(originals[LOGIN_DEFS]),
    }
    for path in _pwquality_paths():
        updates[path] = _set_pwquality(
            originals[path] or "", ensure_all=(path == PWQUALITY)
        )

    if dry_run:
        return result(
            CODE, TITLE, FIXED,
            "dry-run: 복잡도, 최근 비밀번호 4회, 최소 1일/최대 90일 정책 적용 예정",
        )

    backups = []
    for path, old in originals.items():
        if old is None:
            continue
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    for path, content in updates.items():
        if not write_text(path, content):
            _restore(originals)
            return result(CODE, TITLE, FAILED, f"쓰기 실패로 원본 복원: {path}")

    if not _good():
        _restore(originals)
        return result(CODE, TITLE, FAILED, "정책 검증 실패로 원본 복원")

    return result(
        CODE, TITLE, FIXED,
        "비밀번호 복잡도 및 변경주기 정책 적용; "
        f"백업: {summarize(backups)}",
    )

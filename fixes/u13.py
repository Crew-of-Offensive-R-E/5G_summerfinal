"""U-13 안전한 비밀번호 암호화 알고리즘 사용 조치."""

import re

from fix_common import FIXED, FAILED, MANUAL, result, read_text, backup_file, write_text


CODE = "U-13"
TITLE = "안전한 비밀번호 암호화 알고리즘 사용"
LOGIN_DEFS = "/etc/login.defs"
PAM_PASSWORD = "/etc/pam.d/common-password"
SAFE_METHODS = {"SHA512", "SHA-512", "SHA256", "SHA-256", "YESCRYPT"}


def _login_method(text):
    match = re.search(r"(?im)^\s*ENCRYPT_METHOD\s+(\S+)", text)
    return match.group(1).upper() if match else None


def _secure_login_defs(text):
    line = "ENCRYPT_METHOD YESCRYPT"
    pattern = re.compile(r"(?im)^\s*ENCRYPT_METHOD\s+\S+.*$")
    if pattern.search(text):
        return pattern.sub(line, text).rstrip() + "\n"
    return text.rstrip() + "\n\n# KISA U-13\n" + line + "\n"


def _pam_line_secure(line):
    active = line.split("#", 1)[0]
    return (
        re.match(r"^\s*password\b", active) is not None
        and re.search(r"\bpam_unix\.so\b", active) is not None
        and re.search(r"\b(?:yescrypt|sha512|sha256)\b", active) is not None
    )


def _secure_pam(text):
    changed = False
    found = False
    out = []
    for line in text.splitlines():
        active = line.split("#", 1)[0]
        if (
            re.match(r"^\s*password\b", active)
            and re.search(r"\bpam_unix\.so\b", active)
        ):
            found = True
            before_comment, marker, comment = line.partition("#")
            tokens = before_comment.rstrip().split()
            tokens = [
                token for token in tokens
                if token.lower() not in {
                    "md5", "bigcrypt", "sha256", "sha512", "yescrypt",
                    "gost_yescrypt", "blowfish",
                }
            ]
            tokens.append("yescrypt")
            rebuilt = " ".join(tokens)
            if marker:
                rebuilt += "  #" + comment
            out.append(rebuilt)
            changed = changed or rebuilt != line
        else:
            out.append(line)
    return "\n".join(out) + "\n", found, changed


def fix(dry_run=False):
    login_text = read_text(LOGIN_DEFS)
    pam_text = read_text(PAM_PASSWORD)
    if login_text is None:
        return result(CODE, TITLE, FAILED, f"{LOGIN_DEFS} 파일을 읽을 수 없음")
    if pam_text is None:
        return result(CODE, TITLE, FAILED, f"{PAM_PASSWORD} 파일을 읽을 수 없음")

    pam_new, pam_found, _ = _secure_pam(pam_text)
    if not pam_found:
        return result(
            CODE,
            TITLE,
            MANUAL,
            f"{PAM_PASSWORD}에서 password pam_unix.so 규칙을 찾지 못함",
        )

    login_ok = _login_method(login_text) in SAFE_METHODS
    pam_ok = any(_pam_line_secure(line) for line in pam_text.splitlines())
    if login_ok and pam_ok:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: login.defs와 common-password에 YESCRYPT 적용 예정",
        )

    backups = {}
    for path in (LOGIN_DEFS, PAM_PASSWORD):
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups[path] = backup

    login_new = _secure_login_defs(login_text)
    if not write_text(LOGIN_DEFS, login_new) or not write_text(PAM_PASSWORD, pam_new):
        write_text(LOGIN_DEFS, login_text)
        write_text(PAM_PASSWORD, pam_text)
        return result(CODE, TITLE, FAILED, "설정 쓰기 실패로 두 파일 원본 복원")

    login_verify = read_text(LOGIN_DEFS) or ""
    pam_verify = read_text(PAM_PASSWORD) or ""
    if (
        _login_method(login_verify) != "YESCRYPT"
        or not any(_pam_line_secure(line) for line in pam_verify.splitlines())
    ):
        write_text(LOGIN_DEFS, login_text)
        write_text(PAM_PASSWORD, pam_text)
        return result(CODE, TITLE, FAILED, "YESCRYPT 검증 실패로 원본 복원")

    return result(
        CODE,
        TITLE,
        FIXED,
        "향후 변경되는 비밀번호에 YESCRYPT 적용; 기존 비밀번호는 재설정 필요; "
        f"백업: {backups[LOGIN_DEFS]}, {backups[PAM_PASSWORD]}",
    )


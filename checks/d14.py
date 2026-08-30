"""D-14 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF, file_owner_mode_ok, summarize
import os

CODE = "D-14"
TITLE = "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"

VALID_OWNERS = ("root", "mongod", "mongodb")


def _parse_keyfile_path(text):
    """mongod.conf에서 security.keyFile 경로를 추출한다."""
    in_security = False
    for line in text.splitlines():
        stripped = line.strip()
        # 새 최상위 섹션 시작 감지
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_security = stripped == "security:"
            continue
        if in_security and stripped.startswith("keyFile:"):
            path = stripped.split(":", 1)[1].strip().strip("'\"")
            if path:
                return path
    return None


def check():
    if not os.path.isfile(MONGOD_CONF):
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    findings = []

    # 1) mongod.conf 권한 확인 (owner: root/mongod/mongodb, max 644)
    conf_ok = any(
        file_owner_mode_ok(MONGOD_CONF, owner=o, max_mode=0o644)[0]
        for o in VALID_OWNERS
    )
    if not conf_ok:
        _, desc = file_owner_mode_ok(MONGOD_CONF, owner="root", max_mode=0o644)
        findings.append(f"{MONGOD_CONF}: {desc}")

    # 2) mongod.conf 상위 디렉터리 권한 확인
    conf_dir = os.path.dirname(MONGOD_CONF)
    if os.path.isdir(conf_dir):
        dir_ok = any(
            file_owner_mode_ok(conf_dir, owner=o, max_mode=0o755)[0]
            for o in VALID_OWNERS
        )
        if not dir_ok:
            _, desc = file_owner_mode_ok(conf_dir, owner="root", max_mode=0o755)
            findings.append(f"{conf_dir}: {desc}")

    # 3) keyFile 권한 확인 (owner: mongod/mongodb, max 600)
    text = read_text(MONGOD_CONF)
    if text:
        keyfile = _parse_keyfile_path(text)
        if keyfile and os.path.isfile(keyfile):
            key_ok = any(
                file_owner_mode_ok(keyfile, owner=o, max_mode=0o600)[0]
                for o in ("mongod", "mongodb")
            )
            if not key_ok:
                _, desc = file_owner_mode_ok(keyfile, owner="mongod", max_mode=0o600)
                findings.append(f"keyFile({keyfile}): {desc}")

    if findings:
        return result(CODE, TITLE, VULN, summarize(findings))
    return result(CODE, TITLE, GOOD, "주요 설정 파일 접근 권한 적절")

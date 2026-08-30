"""D-19 OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정 조치

판단 기준(확인팀 5G_Check_Tool checks/d19.py 기준): mongod.conf에 security.keyFile이
설정되어 있고 그 파일이 실제로 존재하거나, TLS/X.509 인증서 설정(certificateKeyFile 등)이
있으면 양호. 이 환경은 단일 노드(레플리카셋 아님)라 keyFile이 실제 클러스터 통신에
쓰이진 않지만, 확인팀 판정 기준(파일 존재 여부)을 충족하는 가장 간단하고 안전한 방법은
keyFile을 생성해 지정하는 것이다.

MongoDB는 keyFile 권한이 소유자만 읽기 가능(600)하지 않으면 시작을 거부하므로 반드시
서비스 계정 소유·600으로 생성한다. 재시작 후 mongod가 실제로 기동되는지 확인하고,
실패하면 keyFile/설정을 모두 롤백한다.
"""

import base64
import os

from fix_common import (
    FIXED, FAILED, result,
    backup_file, read_text, write_text, set_conf_scalar,
    set_file_owner, get_service_file_user, run_command,
    MONGOD_CONF,
)

CODE = "D-19"
TITLE = "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
KEYFILE_PATH = "/etc/mongod.keyfile"


def _parse_keyfile_path(text):
    in_security = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_security = stripped == "security:"
            continue
        if in_security and stripped.startswith("keyFile:"):
            path = stripped.split(":", 1)[1].strip().strip("'\"")
            if path:
                return path
    return None


def _has_tls_config(text):
    lower = text.lower()
    return any(k in lower for k in (
        "certificatekeyfile:", "tlscertificatekeyfile:",
        "sslpemkeyfile:", "mode: requiretls", "mode: requiressl", "mode: preferssl",
    ))


def fix(dry_run=False):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    keyfile = _parse_keyfile_path(text)
    has_keyfile = bool(keyfile) and os.path.isfile(keyfile)
    has_tls = _has_tls_config(text)

    if has_keyfile or has_tls:
        return None  # 이미 양호

    service_user = get_service_file_user() or "mongodb"

    if dry_run:
        return result(CODE, TITLE, FIXED,
                      f"dry-run: {KEYFILE_PATH} 생성(600, {service_user} 소유) 후 "
                      f"security.keyFile로 지정 예정")

    key_content = base64.b64encode(os.urandom(500)).decode()
    try:
        with open(KEYFILE_PATH, "w", encoding="utf-8") as fp:
            fp.write(key_content)
        os.chmod(KEYFILE_PATH, 0o600)
    except OSError as exc:
        return result(CODE, TITLE, FAILED, f"{KEYFILE_PATH} 생성 실패: {exc}")

    if not set_file_owner(KEYFILE_PATH, owner=service_user, group=service_user):
        try:
            os.remove(KEYFILE_PATH)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, f"{KEYFILE_PATH} 소유자를 {service_user}로 변경 실패")

    backup_path = backup_file(MONGOD_CONF)
    new_text = set_conf_scalar(text, "security", "keyFile", KEYFILE_PATH)
    if not write_text(MONGOD_CONF, new_text):
        try:
            os.remove(KEYFILE_PATH)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 쓰기 실패(권한 확인)")

    run_command(["systemctl", "daemon-reload"])
    code, _, err = run_command(["systemctl", "restart", "mongod"], timeout=30)

    def _rollback(reason):
        if backup_path:
            run_command(["cp", "-a", backup_path, MONGOD_CONF])
        try:
            os.remove(KEYFILE_PATH)
        except OSError:
            pass
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "restart", "mongod"], timeout=30)
        return result(CODE, TITLE, FAILED, f"{reason} → keyFile 삭제 및 설정 롤백")

    if code != 0:
        return _rollback(f"keyFile 설정 후 mongod 재시작 실패({err})")

    active_code, active_out, _ = run_command(["systemctl", "is-active", "mongod"])
    if active_out.strip() != "active":
        return _rollback(f"재시작 후 mongod가 active 상태 아님(현재: {active_out.strip()})")

    return result(CODE, TITLE, FIXED,
                  f"{KEYFILE_PATH} 생성(600, {service_user} 소유) 후 {MONGOD_CONF}에 "
                  f"security.keyFile 설정(백업: {backup_path}), 재시작 후 정상 기동 확인")

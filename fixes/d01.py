"""D-01 기본 계정의 비밀번호·정책 변경 조치

판단 기준(확인팀 5G_Check_Tool checks/d01.py 기준): mongod.conf의
security.authorization이 enabled면 양호, 아니면(비활성) 취약.
확인팀 check()는 이 값 하나만 보고 판정하며 사용자 계정/롤은 보지 않는다
(추측 가능한 이름의 계정 감사는 이 항목의 확인팀 판정 기준에 포함되지 않음).
"""

from fix_common import (
    FIXED, FAILED, result,
    backup_file, read_text, write_text, set_conf_scalar, is_auth_enabled,
    run_command,
    MONGOD_CONF,
)

CODE = "D-01"
TITLE = "기본 계정의 패스워드, 정책 등을 변경하여 사용"


def fix(dry_run=False):
    if is_auth_enabled():
        return None  # 이미 양호

    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: security.authorization: enabled 설정 예정")

    backup_path = backup_file(MONGOD_CONF)
    if backup_path is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 백업 실패로 조치를 건너뜀")

    new_text = set_conf_scalar(text, "security", "authorization", "enabled")
    if not write_text(MONGOD_CONF, new_text):
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 쓰기 실패(권한 확인)")

    run_command(["systemctl", "daemon-reload"])
    code, _, err = run_command(["systemctl", "restart", "mongod"], timeout=30)
    if code != 0:
        run_command(["cp", "-a", backup_path, MONGOD_CONF])
        run_command(["systemctl", "restart", "mongod"], timeout=30)
        return result(CODE, TITLE, FAILED, f"authorization 활성화 후 재시작 실패({err}) → 백업에서 롤백")

    if not is_auth_enabled():
        run_command(["cp", "-a", backup_path, MONGOD_CONF])
        run_command(["systemctl", "restart", "mongod"], timeout=30)
        return result(CODE, TITLE, FAILED, "재검증 실패(authorization이 여전히 비활성) → 롤백")

    return result(CODE, TITLE, FIXED,
                  f"{MONGOD_CONF}의 security.authorization을 enabled로 설정(백업: {backup_path}), "
                  "재시작 후 재검증 완료")

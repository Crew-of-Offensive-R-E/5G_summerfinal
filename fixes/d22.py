"""D-22 데이터베이스의 자원 제한 기능을 TRUE로 설정 조치

판단 기준(확인팀 5G_Check_Tool checks/d22.py 기준): mongod.conf에
net.maxIncomingConnections이 설정되어 있고 그 값이 MongoDB 기본값(65536) 미만이면 양호.
"""

from fix_common import (
    FIXED, FAILED, result,
    backup_file, read_text, write_text, set_conf_scalar, run_command,
    MONGOD_CONF,
)

CODE = "D-22"
TITLE = "데이터베이스의 자원 제한 기능을 TRUE로 설정"
DEFAULT_MAX_CONN = 65536
TARGET_MAX_CONN = 1000  # Open5GS 랩 환경 기준 충분히 여유 있는 상한


def _current_max_conn(text):
    max_conn = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "maxIncomingConnections:" in s:
            try:
                max_conn = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
    return max_conn


def fix(dry_run=False):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    current = _current_max_conn(text)
    if current is not None and current < DEFAULT_MAX_CONN:
        return None  # 이미 양호

    if dry_run:
        return result(CODE, TITLE, FIXED,
                      f"dry-run: net.maxIncomingConnections={current or '(미설정)'} → "
                      f"{TARGET_MAX_CONN} 설정 예정")

    backup_path = backup_file(MONGOD_CONF)
    new_text = set_conf_scalar(text, "net", "maxIncomingConnections", TARGET_MAX_CONN)
    if not write_text(MONGOD_CONF, new_text):
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 쓰기 실패(권한 확인)")

    run_command(["systemctl", "daemon-reload"])
    code, _, err = run_command(["systemctl", "restart", "mongod"], timeout=30)

    def _rollback(reason):
        if backup_path:
            run_command(["cp", "-a", backup_path, MONGOD_CONF])
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "restart", "mongod"], timeout=30)
        return result(CODE, TITLE, FAILED, f"{reason} → 롤백")

    if code != 0:
        return _rollback(f"maxIncomingConnections 설정 후 mongod 재시작 실패({err})")

    text_after = read_text(MONGOD_CONF)
    after = _current_max_conn(text_after) if text_after else None
    active_code, active_out, _ = run_command(["systemctl", "is-active", "mongod"])
    if active_out.strip() != "active" or after != TARGET_MAX_CONN:
        return _rollback(f"재검증 실패(active={active_out.strip()}, maxIncomingConnections={after})")

    return result(CODE, TITLE, FIXED,
                  f"net.maxIncomingConnections={current or '(미설정)'} → {TARGET_MAX_CONN} 설정"
                  f"(백업: {backup_path}), 재시작 후 재검증 완료")

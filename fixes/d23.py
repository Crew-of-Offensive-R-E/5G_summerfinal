"""D-23 xp_cmdshell 사용 제한 조치

판단 기준(확인팀 checks/d23.py 기준): mongod.conf에 security.javascriptEnabled가
false로 설정되어 있으면 양호. 미설정(기본값 true) 또는 true면 취약.

조치: security.javascriptEnabled를 false로 설정하고 mongod 재시작.
"""

from fix_common import (
    FIXED, FAILED, result,
    backup_file, read_text, write_text, set_conf_scalar, run_command,
    MONGOD_CONF,
)

CODE = "D-23"
TITLE = "xp_cmdshell 사용 제한"


def _get_js_enabled(text):
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "javascriptEnabled:" in s:
            return s.split(":", 1)[1].strip().strip('"').strip("'").lower()
    return None


def fix(dry_run=False):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    current = _get_js_enabled(text)
    if current == "false":
        return None  # 이미 양호

    if dry_run:
        return result(CODE, TITLE, FIXED,
                      f"dry-run: javascriptEnabled={current or '(미설정)'} → false 설정 예정")

    backup_path = backup_file(MONGOD_CONF)
    new_text = set_conf_scalar(text, "security", "javascriptEnabled", "false")
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
        return _rollback(f"javascriptEnabled 설정 후 mongod 재시작 실패({err})")

    active_code, active_out, _ = run_command(["systemctl", "is-active", "mongod"])
    if active_out.strip() != "active":
        return _rollback(f"재시작 후 mongod가 active 상태 아님(현재: {active_out.strip()})")

    return result(CODE, TITLE, FIXED,
                  f"javascriptEnabled={current or '(미설정)'} → false 설정"
                  f"(백업: {backup_path}), 재시작 후 정상 기동 확인")

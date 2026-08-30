"""D-07 root 권한으로 서비스 구동 제한 조치

판단 기준(가이드): mongod가 root 계정/권한이 아닌 별도 계정으로 구동되면 양호.
mongod가 현재 비활성 상태라면 서비스를 임의로 기동/재시작해서 판정을 만들어내지 않고,
systemd 서비스 파일(User=/Group=)에 이미 non-root 계정이 설정돼 있는지로만 판단한다
(부팅 순서 이슈로 인한 서비스 다운 복구는 이 항목의 책임 범위가 아님).
"""

from fix_common import (
    FIXED, FAILED, result,
    backup_file, read_text, write_text,
    get_mongod_process_user, get_service_file_user, restart_mongod,
    run_command, owner_name,
    MONGOD_SERVICE,
)

CODE = "D-07"
TITLE = "root 권한으로 서비스 구동 제한"
TARGET_USER = "mongodb"


def _dir_owner(path):
    if not path:
        return None
    try:
        return owner_name(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _set_service_user(text, target):
    lines = text.splitlines()
    out, user_set, group_set = [], False, False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("User="):
            out.append(f"User={target}")
            user_set = True
        elif stripped.startswith("Group="):
            out.append(f"Group={target}")
            group_set = True
        else:
            out.append(line)
    if not user_set or not group_set:
        final = []
        for line in out:
            final.append(line)
            if line.strip() == "[Service]":
                if not user_set:
                    final.append(f"User={target}")
                if not group_set:
                    final.append(f"Group={target}")
        out = final
    return "\n".join(out) + "\n"


def fix(dry_run=False):
    # 실제 실행 중인 프로세스 소유자가 확인되면 그 값이 가장 신뢰도 높은 증거다.
    proc_user = get_mongod_process_user()
    if proc_user is not None:
        if proc_user != "root":
            return None  # 이미 양호
        before_detail = f"실행 중인 mongod 프로세스 사용자=root"
    else:
        # mongod가 비활성 상태 — 서비스 기동은 이 항목 책임이 아니므로 정적 설정만으로 판단.
        service_user = get_service_file_user()
        if service_user and service_user != "root":
            return None  # 서비스 파일에 이미 non-root 계정 설정됨 (양호로 판단, 기동은 강제하지 않음)
        before_detail = f"mongod 비활성 상태, 서비스 파일 User={service_user or '(미설정)'}"

    text = read_text(MONGOD_SERVICE)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{before_detail}, {MONGOD_SERVICE} 읽기 실패")

    backup_path = backup_file(MONGOD_SERVICE)
    new_text = _set_service_user(text, TARGET_USER)

    if dry_run:
        return result(CODE, TITLE, FIXED,
                      f"{before_detail}. dry-run: {MONGOD_SERVICE} User/Group→{TARGET_USER} 예정"
                      + (f" (백업: {backup_path})" if backup_path else ""))

    if not write_text(MONGOD_SERVICE, new_text):
        return result(CODE, TITLE, FAILED, f"{before_detail}, {MONGOD_SERVICE} 쓰기 실패(권한 확인)")

    # mongod가 이미 실행 중이었을 때만(=root로 구동 중이었을 때만) 재적용을 위해 재시작한다.
    if proc_user == "root":
        ok, detail = restart_mongod()
        if not ok:
            if backup_path:
                run_command(["cp", "-a", backup_path, MONGOD_SERVICE])
                run_command(["systemctl", "daemon-reload"])
            return result(CODE, TITLE, FAILED,
                          f"{before_detail}, 서비스 파일 조치 후 재시작 실패({detail}) → 백업에서 롤백")

        after_user = get_mongod_process_user()
        if after_user == "root" or after_user is None:
            if backup_path:
                run_command(["cp", "-a", backup_path, MONGOD_SERVICE])
                run_command(["systemctl", "daemon-reload"])
                restart_mongod()
            return result(CODE, TITLE, FAILED,
                          f"{before_detail}, 재시작 후 재검증 실패(실행 사용자={after_user}) → 롤백")

        return result(CODE, TITLE, FIXED,
                      f"{before_detail}. {MONGOD_SERVICE} User/Group→{TARGET_USER} 변경(백업: {backup_path}), "
                      f"재시작 후 실행 사용자={after_user} 재검증 완료")

    return result(CODE, TITLE, FIXED,
                  f"{before_detail}. {MONGOD_SERVICE} User/Group→{TARGET_USER} 변경(백업: {backup_path}). "
                  f"mongod가 비활성 상태라 재시작은 수행하지 않음 — 다음 기동 시 반영, 기동 후 재검증 필요")

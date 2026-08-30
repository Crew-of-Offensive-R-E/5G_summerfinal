"""D-14 주요 설정 파일 및 디렉터리 접근 권한 설정 조치

판단 기준(가이드): 주요 설정 파일에 일반 사용자(others)의 수정 권한이 없고,
권한이 640 이하로 설정되어 있으면 양호.

주의:
- mongod 프로세스는 systemd 서비스 파일(User=/Group=)에 설정된 계정으로 구동된다.
  소유자·그룹을 확인하지 않고 무작정 640으로 좁히면 그 계정이 설정 파일을 읽지 못해
  mongod가 "다음" 기동 시 실패할 수 있다 — 그룹을 서비스 계정으로 맞춘 뒤 640을 적용한다.
- 이 환경은 docker open5gs-net 생성 시점과 mongod 시작 순서에 따른 별도의 exit code 48
  이슈가 있다(D-14와 무관한 별도 TODO). 이 조치가 그 문제와 섞이지 않도록 mongod를
  재시작하지 않는다 — 재검증은 `su <서비스계정> -c "test -r <파일>"` 로 "재시작 없이"
  실제 읽기 권한만 확인하고, 실패하면 원래 소유자·그룹·권한으로 롤백한다.
"""

import stat

from fix_common import (
    FIXED, FAILED, result,
    backup_file, owner_name, set_file_mode, set_file_owner,
    get_service_file_user, run_command, read_text,
    MONGOD_CONF,
)

CODE = "D-14"
TITLE = "주요 설정 파일 및 디렉터리 접근 권한 설정"
TARGET_MODE = 0o640


def _group_name(path):
    import grp
    import os
    try:
        st = os.stat(path)
        return grp.getgrgid(st.st_gid).gr_name
    except (FileNotFoundError, PermissionError, OSError, KeyError):
        return None


def _mode(path):
    import os
    return stat.S_IMODE(os.stat(path).st_mode)


def _target_files():
    import os
    files = [MONGOD_CONF]
    text = read_text(MONGOD_CONF)
    if text:
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("keyFile:"):
                key_path = s.split(":", 1)[1].strip().strip('"').strip("'")
                if key_path:
                    files.append(key_path)
    return [f for f in files if os.path.exists(f)]


def _is_ok(path):
    mode = _mode(path)
    return not (mode & stat.S_IWOTH) and mode <= TARGET_MODE


def _can_read_as(service_user, path):
    """mongod를 재시작하지 않고, 서비스 계정 권한으로 실제 읽기 가능한지만 확인한다."""
    code, _, _ = run_command(["su", service_user, "-s", "/bin/sh", "-c", f"test -r '{path}'"], timeout=5)
    return code == 0


def fix(dry_run=False):
    targets = _target_files()
    if not targets:
        return result(CODE, TITLE, FAILED, "점검 대상 설정 파일을 찾을 수 없음")

    vulnerable = [f for f in targets if not _is_ok(f)]
    if not vulnerable:
        return None  # 이미 양호

    service_user = get_service_file_user() or "mongodb"
    fixed_entries, failed_entries = [], []

    for path in vulnerable:
        before_mode = oct(_mode(path))
        before_owner = owner_name(path)
        before_group = _group_name(path)

        if dry_run:
            fixed_entries.append(
                f"{path}: {before_owner}:{before_group} {before_mode} → root:{service_user} 640 (dry-run, "
                "mongod 재시작 없음)"
            )
            continue

        backup_path = backup_file(path)

        owner_ok = set_file_owner(path, owner="root", group=service_user)
        mode_ok = set_file_mode(path, TARGET_MODE)

        def _rollback():
            set_file_owner(path, owner=before_owner, group=before_group)
            set_file_mode(path, int(before_mode, 8))

        if not owner_ok or not mode_ok:
            _rollback()
            failed_entries.append(f"{path}(소유자/권한 변경 실패 → 롤백)")
            continue

        # 1) stat으로 실제 변경 결과 확인
        after_mode = oct(_mode(path))
        after_owner = owner_name(path)
        after_group = _group_name(path)
        stat_ok = (after_mode == oct(TARGET_MODE) and after_owner == "root" and after_group == service_user)

        # 2) mongod 재시작 없이, 서비스 계정으로 실제 읽기 가능한지 확인
        readable = _can_read_as(service_user, path) if stat_ok else False

        if not stat_ok or not readable:
            _rollback()
            failed_entries.append(
                f"{path}(재검증 실패: mode={after_mode}, owner={after_owner}:{after_group}, "
                f"{service_user} 읽기 가능={readable} → 원본 {before_owner}:{before_group} {before_mode}로 롤백)"
            )
            continue

        fixed_entries.append(
            f"{path}: 원본 {before_owner}:{before_group} {before_mode} → root:{service_user} 640, "
            f"{service_user} 계정 읽기 가능 확인(재시작 없음, 백업: {backup_path})"
        )

    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: " + "; ".join(fixed_entries))

    if not fixed_entries:
        return result(CODE, TITLE, FAILED, "; ".join(failed_entries) or "조치 실패")

    status = FIXED if not failed_entries else FAILED
    detail = "; ".join(fixed_entries)
    if failed_entries:
        detail += " | 실패: " + "; ".join(failed_entries)
    return result(CODE, TITLE, status, detail)

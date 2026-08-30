"""U-29 /etc/hosts.lpd 파일 소유자 및 권한 설정 조치."""

import os
import stat

from fix_common import FIXED, FAILED, result, backup_file, set_file_mode, set_file_owner


CODE = "U-29"
TITLE = "hosts.lpd 소유자 및 권한"
TARGET = "/etc/hosts.lpd"


def _state():
    try:
        info = os.stat(TARGET)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    return info, stat.S_IMODE(info.st_mode)


def fix(dry_run=False):
    state = _state()
    if state is None:
        return None
    if state is False:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일 상태 확인 실패")

    info, mode = state
    if info.st_uid == 0 and mode <= 0o600:
        return None
    if dry_run:
        return result(CODE, TITLE, FIXED, f"dry-run: {TARGET} 소유자 root, 권한 0600 적용 예정")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 백업 실패")

    old_uid, old_gid, old_mode = info.st_uid, info.st_gid, mode
    if not set_file_owner(TARGET, "root") or not set_file_mode(TARGET, 0o600):
        try:
            os.chown(TARGET, old_uid, old_gid)
            os.chmod(TARGET, old_mode)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, "소유자/권한 변경 실패로 복원 시도")

    verify = _state()
    if not verify or verify[0].st_uid != 0 or verify[1] > 0o600:
        try:
            os.chown(TARGET, old_uid, old_gid)
            os.chmod(TARGET, old_mode)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, "변경 검증 실패로 복원 시도")

    return result(CODE, TITLE, FIXED, f"소유자 root, 권한 0600 적용; 백업: {backup}")


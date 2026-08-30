"""U-18 /etc/shadow 파일 소유자 및 권한 설정 조치."""

import os
import stat

from fix_common import FIXED, FAILED, result, backup_file, set_file_mode, set_file_owner


CODE = "U-18"
TITLE = "/etc/shadow 파일 소유자 및 권한"
TARGET = "/etc/shadow"


def _state():
    try:
        info = os.stat(TARGET)
    except OSError:
        return None
    return info, stat.S_IMODE(info.st_mode)


def fix(dry_run=False):
    state = _state()
    if state is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일이 없음")
    info, mode = state
    if info.st_uid == 0 and mode <= 0o400:
        return None

    if dry_run:
        return result(CODE, TITLE, FIXED, f"dry-run: {TARGET} 소유자 root, 권한 0400 적용 예정")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 백업 실패")

    old_uid, old_gid, old_mode = info.st_uid, info.st_gid, mode
    if not set_file_owner(TARGET, "root") or not set_file_mode(TARGET, 0o400):
        try:
            os.chown(TARGET, old_uid, old_gid)
            os.chmod(TARGET, old_mode)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, "소유자/권한 변경 실패로 메타데이터 복원 시도")

    verify = _state()
    if verify is None or verify[0].st_uid != 0 or verify[1] > 0o400:
        try:
            os.chown(TARGET, old_uid, old_gid)
            os.chmod(TARGET, old_mode)
        except OSError:
            pass
        return result(CODE, TITLE, FAILED, "변경 검증 실패로 메타데이터 복원 시도")

    return result(CODE, TITLE, FIXED, f"소유자 root, 권한 0400 적용; 백업: {backup}")


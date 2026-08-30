"""U-21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정 조치."""

import os
import stat

from fix_common import FIXED, FAILED, result, backup_file, summarize


CODE = "U-21"
TITLE = "/etc/(r)syslog.conf 소유자 및 권한"
TARGETS = ("/etc/rsyslog.conf", "/etc/syslog.conf")


def _bad_files():
    bad = []
    for path in TARGETS:
        try:
            info = os.stat(path)
        except FileNotFoundError:
            continue
        except OSError:
            bad.append((path, None, None, None))
            continue
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0 or mode > 0o640:
            bad.append((path, info.st_uid, info.st_gid, mode))
    return bad


def _restore(changed):
    for path, uid, gid, mode in reversed(changed):
        try:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        except OSError:
            pass


def fix(dry_run=False):
    existing = [path for path in TARGETS if os.path.exists(path)]
    if not existing:
        return None

    bad = _bad_files()
    if not bad:
        return None
    unreadable = [path for path, uid, _, _ in bad if uid is None]
    if unreadable:
        return result(CODE, TITLE, FAILED, "파일 상태 확인 실패: " + summarize(unreadable))

    paths = [item[0] for item in bad]
    changes = [
        f"{path}(uid={uid},mode={mode:04o})->root:0640"
        for path, uid, _, mode in bad
    ]
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: " + summarize(changes))

    backups = []
    for path in paths:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    changed = []
    for path, uid, gid, mode in bad:
        changed.append((path, uid, gid, mode))
        try:
            os.chown(path, 0, gid)
            os.chmod(path, 0o640)
        except OSError as exc:
            _restore(changed)
            return result(CODE, TITLE, FAILED, f"{path} 변경 실패, 복원 시도: {exc}")

    if _bad_files():
        _restore(changed)
        return result(CODE, TITLE, FAILED, "변경 검증 실패로 메타데이터 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "root 소유, 0640 적용: " + summarize(changes)
        + "; 백업: " + summarize(backups),
    )

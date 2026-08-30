"""U-17 시스템 시작 스크립트 권한 설정 조치."""

import glob
import os
import stat

from fix_common import FIXED, FAILED, result, backup_file, summarize


CODE = "U-17"
TITLE = "시스템 시작 스크립트 권한"
PATTERNS = (
    "/etc/init.d/*",
    "/etc/systemd/system/*.service",
    "/lib/systemd/system/*.service",
)


def _bad_files():
    bad = []
    for pattern in PATTERNS:
        for path in glob.glob(pattern):
            try:
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                info = os.stat(path)
                mode = stat.S_IMODE(info.st_mode)
                if info.st_uid != 0 or mode > 0o755 or mode & stat.S_IWOTH:
                    bad.append((path, info.st_uid, info.st_gid, mode))
            except OSError:
                continue
    return sorted(set(bad))


def fix(dry_run=False):
    bad = _bad_files()
    if not bad:
        return None

    paths = [item[0] for item in bad]
    changes = [
        f"{path}(uid={uid},mode={mode:04o})->root:{mode & 0o755:04o}"
        for path, uid, _, mode in bad
    ]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 소유자 root 및 일반 사용자 쓰기 제거 예정: "
            + summarize(changes, limit=10),
        )

    backups = []
    for path, _, _, _ in bad:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    changed = []
    for path, uid, gid, mode in bad:
        target_mode = mode & 0o755
        try:
            os.chown(path, 0, gid)
            os.chmod(path, target_mode)
            changed.append((path, uid, gid, mode))
        except OSError as exc:
            for old_path, old_uid, old_gid, old_mode in reversed(changed):
                try:
                    os.chown(old_path, old_uid, old_gid)
                    os.chmod(old_path, old_mode)
                except OSError:
                    pass
            return result(CODE, TITLE, FAILED, f"{path} 변경 실패, 복원 시도: {exc}")

    if _bad_files():
        for path, uid, gid, mode in reversed(changed):
            try:
                os.chown(path, uid, gid)
                os.chmod(path, mode)
            except OSError:
                pass
        return result(CODE, TITLE, FAILED, "시작 스크립트 검증 실패로 메타데이터 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "시작 스크립트 소유자 root 및 g/o 쓰기·특수 권한 제거: "
        + summarize(changes, limit=10)
        + "; 백업: "
        + summarize(backups, limit=10),
    )

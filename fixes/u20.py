"""U-20 /etc/(x)inetd.conf 및 systemd 설정 소유자·권한 조치."""

import os
import stat
from pathlib import Path

from fix_common import FIXED, FAILED, result, backup_file, summarize


CODE = "U-20"
TITLE = "/etc/(x)inetd.conf 소유자 및 권한"
CONFIG_FILES = (
    "/etc/inetd.conf",
    "/etc/xinetd.conf",
    "/etc/systemd/system.conf",
)
XINETD_DIR = "/etc/xinetd.d"


def _targets():
    targets = [(path, 0o600) for path in CONFIG_FILES if Path(path).is_file()]
    root = Path(XINETD_DIR)
    if root.is_dir():
        targets.append((str(root), 0o700))
        for path in root.rglob("*"):
            if path.is_symlink():
                continue
            targets.append((str(path), 0o700 if path.is_dir() else 0o600))
    return targets


def _bad_targets():
    bad = []
    for path, max_mode in _targets():
        try:
            info = os.stat(path)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != 0 or mode > max_mode:
                bad.append((path, max_mode, info.st_uid, info.st_gid, mode))
        except OSError:
            continue
    return bad


def fix(dry_run=False):
    targets = _targets()
    if not targets:
        return None
    bad = _bad_targets()
    if not bad:
        return None

    paths = [item[0] for item in bad]
    changes = [
        f"{path}(uid={uid},mode={old_mode:04o})->root:{target_mode:04o}"
        for path, target_mode, uid, _, old_mode in bad
    ]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: root 소유 및 설정 파일 0600/디렉터리 0700 적용 예정: "
            + summarize(changes, limit=10),
        )

    backups = []
    for path, _, _, _, _ in bad:
        # backup_file()은 일반 파일용이다. 디렉터리는 아래에 기록한
        # uid/gid/mode로 실패 시 복원한다.
        if os.path.isfile(path):
            backup = backup_file(path)
            if backup is None:
                return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
            backups.append(backup)

    changed = []
    for path, target_mode, uid, gid, old_mode in bad:
        try:
            os.chown(path, 0, gid)
            os.chmod(path, target_mode)
            changed.append((path, uid, gid, old_mode))
        except OSError as exc:
            for old_path, old_uid, old_gid, restore_mode in reversed(changed):
                try:
                    os.chown(old_path, old_uid, old_gid)
                    os.chmod(old_path, restore_mode)
                except OSError:
                    pass
            return result(CODE, TITLE, FAILED, f"{path} 변경 실패, 복원 시도: {exc}")

    if _bad_targets():
        for path, uid, gid, old_mode in reversed(changed):
            try:
                os.chown(path, uid, gid)
                os.chmod(path, old_mode)
            except OSError:
                pass
        return result(CODE, TITLE, FAILED, "권한 검증 실패로 메타데이터 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "root 소유 및 설정 파일 0600/디렉터리 0700 적용: "
        + summarize(changes, limit=10)
        + "; 파일 백업: "
        + (summarize(backups, limit=10) if backups else "없음(디렉터리 메타데이터만 변경)"),
    )

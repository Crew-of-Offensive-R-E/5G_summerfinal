"""U-24 사용자·시스템 환경변수 파일 소유자 및 권한 설정 조치."""

import os
import stat

from fix_common import FIXED, FAILED, MANUAL, result, parse_passwd, backup_file, summarize


CODE = "U-24"
TITLE = "환경변수 파일 소유자 및 권한"
FILES = (
    ".profile", ".bashrc", ".bash_profile", ".bash_login", ".cshrc",
    ".kshrc", ".login", ".exrc", ".netrc",
)


def _targets():
    items = []
    symlinks = []
    seen = set()
    for user in parse_passwd():
        home = user["home"]
        if not home or not os.path.isdir(home):
            continue
        for filename in FILES:
            path = os.path.join(home, filename)
            if not os.path.lexists(path) or path in seen:
                continue
            seen.add(path)
            if os.path.islink(path):
                symlinks.append(path)
                continue
            try:
                info = os.stat(path)
            except OSError:
                continue
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid not in (0, user["uid"]) or mode & 0o022:
                target_uid = info.st_uid if info.st_uid in (0, user["uid"]) else user["uid"]
                items.append((path, target_uid, info.st_uid, info.st_gid, mode))
    return items, symlinks


def _restore(changed):
    for path, uid, gid, mode in reversed(changed):
        try:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        except OSError:
            pass


def fix(dry_run=False):
    bad, symlinks = _targets()
    if symlinks:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "환경파일 심볼릭 링크의 실제 대상을 확인해야 함: " + summarize(symlinks),
        )
    if not bad:
        return None

    paths = [item[0] for item in bad]
    changes = [
        f"{path}(uid={old_uid},mode={mode:04o})->"
        f"uid={target_uid},mode={mode & ~0o022:04o}"
        for path, target_uid, old_uid, _, mode in bad
    ]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: root/해당 계정 소유 및 g/o 쓰기 제거 예정: "
            + summarize(changes),
        )

    backups = []
    for path in paths:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    changed = []
    for path, target_uid, old_uid, gid, mode in bad:
        changed.append((path, old_uid, gid, mode))
        try:
            os.chown(path, target_uid, gid)
            os.chmod(path, mode & ~0o022)
        except OSError as exc:
            _restore(changed)
            return result(CODE, TITLE, FAILED, f"{path} 변경 실패, 복원 시도: {exc}")

    remaining, remaining_links = _targets()
    if remaining or remaining_links:
        _restore(changed)
        return result(CODE, TITLE, FAILED, "변경 검증 실패로 메타데이터 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "환경파일 소유자 정정 및 그룹/기타 사용자 쓰기 제거: "
        + summarize(changes)
        + "; 백업: "
        + summarize(backups),
    )

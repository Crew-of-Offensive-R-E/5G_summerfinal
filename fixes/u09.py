"""U-09 계정이 참조하는 GID가 /etc/group에 존재하도록 조치."""

import grp
import shutil
from collections import defaultdict
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    result,
    parse_passwd,
    read_text,
    backup_file,
    command_exists,
    run_command,
    summarize,
)


CODE = "U-09"
TITLE = "계정이 존재하지 않는 GID 금지"
GROUP_FILES = ("/etc/group", "/etc/gshadow")


def _missing_gids():
    group_text = read_text("/etc/group") or ""
    existing = set()
    for line in group_text.splitlines():
        parts = line.split(":")
        if line and not line.startswith("#") and len(parts) >= 3:
            try:
                existing.add(int(parts[2]))
            except ValueError:
                continue
    missing = defaultdict(list)
    for user in parse_passwd():
        if user["gid"] not in existing:
            missing[user["gid"]].append(user["name"])
    return dict(missing)


def _group_name(gid, users, used_names):
    preferred = users[0]
    if preferred not in used_names:
        return preferred
    base = f"kisa_gid_{gid}"
    name = base
    suffix = 1
    while name in used_names:
        name = f"{base}_{suffix}"
        suffix += 1
    return name


def _restore(backups, created_groups):
    for name in reversed(created_groups):
        run_command(["groupdel", name], timeout=15)
    for original, backup in backups.items():
        try:
            shutil.copy2(backup, original)
        except OSError:
            pass


def fix(dry_run=False):
    missing = _missing_gids()
    if not missing:
        return None
    if not command_exists("groupadd") or not command_exists("groupdel"):
        return result(CODE, TITLE, FAILED, "groupadd/groupdel 명령을 찾을 수 없음")

    used_names = {group.gr_name for group in grp.getgrall()}
    assignments = []
    for gid, users in sorted(missing.items()):
        name = _group_name(gid, users, used_names)
        assignments.append((gid, name, users))
        used_names.add(name)
    detail_items = [
        f"GID {gid}->{name}({','.join(users)})"
        for gid, name, users in assignments
    ]
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: " + summarize(detail_items))

    backups = {}
    for path in GROUP_FILES:
        if not Path(path).exists():
            continue
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups[path] = backup

    created = []
    for gid, name, _ in assignments:
        code, output, error = run_command(
            ["groupadd", "-g", str(gid), name], timeout=15
        )
        if code != 0:
            _restore(backups, created)
            return result(
                CODE, TITLE, FAILED,
                f"GID {gid} 그룹 생성 실패로 원본 복원: {error or output}",
            )
        created.append(name)

    if _missing_gids():
        _restore(backups, created)
        return result(CODE, TITLE, FAILED, "GID 조치 검증 실패로 원본 복원")

    return result(
        CODE, TITLE, FIXED,
        "계정이 참조하는 미존재 GID 그룹 생성: "
        + summarize(detail_items)
        + "; 백업: "
        + summarize(list(backups.values())),
    )

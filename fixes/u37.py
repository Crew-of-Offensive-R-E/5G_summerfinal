"""U-37 crontab/at 설정 파일 소유자 및 권한 조치."""

import os
import stat

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    result,
    restore_backups,
    set_file_mode,
    set_file_owner,
    summarize,
)


CODE = "U-37"
TITLE = "crontab 설정파일 권한 설정 미흡"

CMD_FILES = ("/usr/bin/crontab", "/usr/bin/at")
CONFIG_FILES = (
    "/etc/cron.allow",
    "/etc/cron.deny",
    "/etc/crontab",
    "/etc/at.allow",
    "/etc/at.deny",
)
DIRS = (
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/var/spool/at",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
)


def _get_issues():
    """확인팀과 동일하게 실행·설정 파일과 cron/at 디렉터리를 판정한다."""
    issues = []
    targets = [(path, 0o750, "file") for path in CMD_FILES]
    targets.extend((path, 0o640, "file") for path in CONFIG_FILES)
    targets.extend((path, 0o750, "dir") for path in DIRS)

    for path, max_mode, kind in targets:
        if not os.path.exists(path):
            continue
        try:
            file_stat = os.stat(path)
            mode = stat.S_IMODE(file_stat.st_mode)
            if file_stat.st_uid != 0 or mode > max_mode:
                issues.append(
                    {
                        "path": path,
                        "max_mode": max_mode,
                        "kind": kind,
                        "mode": mode,
                        "detail": (
                            f"{path}: UID={file_stat.st_uid}, 권한={mode:03o}, "
                            f"기준=root/{max_mode:03o} 이하"
                        ),
                    }
                )
        except (PermissionError, OSError) as exc:
            issues.append(
                {
                    "path": path,
                    "max_mode": max_mode,
                    "kind": kind,
                    "mode": None,
                    "detail": f"{path}: 상태 확인 실패({exc})",
                }
            )
    return issues


def fix(dry_run=False):
    before = _get_issues()
    if not before:
        return None

    before_details = [item["detail"] for item in before]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: root 소유 및 기준 권한으로 조치 예정 — {summarize(before_details)}",
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    directory_metadata = []
    for item in before:
        path = item["path"]
        if item["kind"] == "dir":
            try:
                current_stat = os.stat(path)
                directory_metadata.append((path, stat.S_IMODE(current_stat.st_mode), current_stat.st_uid, current_stat.st_gid))
            except (PermissionError, OSError) as exc:
                errors.append(f"{path}: 디렉터리 메타데이터 저장 실패({exc})")
                continue
        else:
            backup = backup_file(path)
            if backup is None:
                errors.append(f"{path}: 백업 실패로 변경하지 않음")
                continue
            backups.append(backup)

        current_mode = item["mode"]
        target_mode = item["max_mode"]
        if current_mode is not None and current_mode <= target_mode:
            target_mode = current_mode

        if not set_file_mode(path, target_mode):
            errors.append(f"{path}: 권한 {target_mode:03o} 변경 실패")
            continue
        if not set_file_owner(path, "root", "root"):
            errors.append(f"{path}: 소유자 root:root 변경 실패")

    remaining = _get_issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        for path, mode, uid, gid in reversed(directory_metadata):
            try:
                os.chmod(path, mode)
                if hasattr(os, "chown"):
                    os.chown(path, uid, gid)
            except (PermissionError, OSError) as exc:
                restore_errors.append(f"{path}: 디렉터리 메타데이터 원복 실패({exc})")
        details = []
        if errors:
            details.append(f"오류: {summarize(errors)}")
        if remaining:
            details.append(
                "남은 취약 파일: "
                + summarize([item["detail"] for item in remaining])
            )
        if restore_errors:
            details.append(f"원복 오류: {summarize(restore_errors)}")
        elif backups:
            details.append("변경 파일/메타데이터 원복 완료")
        if backups:
            details.append(f"백업: {summarize(backups)}")
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(
        CODE,
        TITLE,
        FIXED,
        "crontab/at 실행·설정 파일을 root:root 및 기준 권한 이하로 조치"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

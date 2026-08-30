"""U-04 비밀번호 파일 보호 조치."""

import shutil
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    result,
    read_text,
    backup_file,
    command_exists,
    run_command,
    summarize,
)


CODE = "U-04"
TITLE = "비밀번호 파일 보호"
PASSWD = "/etc/passwd"
SHADOW = "/etc/shadow"


def _shadow_enabled():
    text = read_text(PASSWD)
    if text is None or not Path(SHADOW).exists():
        return False
    entries = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 2:
            entries.append(fields[1])
    return bool(entries) and all(value == "x" for value in entries)


def _rollback(backups, shadow_existed):
    for original, backup in backups.items():
        try:
            shutil.copy2(backup, original)
        except OSError:
            pass
    if not shadow_existed:
        try:
            Path(SHADOW).unlink(missing_ok=True)
        except OSError:
            pass


def fix(dry_run=False):
    if _shadow_enabled():
        return None
    if not command_exists("pwconv"):
        return result(CODE, TITLE, FAILED, "pwconv 명령을 찾을 수 없음")

    if read_text(PASSWD) is None:
        return result(CODE, TITLE, FAILED, f"{PASSWD} 파일을 읽을 수 없음")

    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: pwconv로 shadow 비밀번호 적용 예정")

    shadow_existed = Path(SHADOW).exists()
    backups = {}
    for path in (PASSWD, SHADOW):
        if not Path(path).exists():
            continue
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups[path] = backup

    code, output, error = run_command(["pwconv"], timeout=30)
    if code != 0 or not _shadow_enabled():
        _rollback(backups, shadow_existed)
        return result(
            CODE, TITLE, FAILED,
            f"pwconv 적용 실패: {error or output or '적용값 검증 실패'}; "
            f"원본 복원, 백업: {summarize(list(backups.values()))}",
        )

    return result(
        CODE, TITLE, FIXED,
        f"pwconv로 shadow 비밀번호 적용; "
        f"백업: {summarize(list(backups.values()))}",
    )

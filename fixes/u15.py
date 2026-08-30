"""U-15 파일 및 디렉터리 소유자 설정 - 소유권 정책 확인이 필요한 항목."""

from fix_common import MANUAL, FAILED, result, command_exists, run_command, summarize


CODE = "U-15"
TITLE = "파일 및 디렉터리 소유자 설정"


def _orphans():
    code, output, error = run_command(
        [
            "find", "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")",
            "-print",
        ],
        timeout=60,
    )
    if code != 0:
        return None, error or output or f"find exit={code}"
    return [line for line in output.splitlines() if line], ""


def fix(dry_run=False):
    if not command_exists("find"):
        return result(CODE, TITLE, FAILED, "find 명령을 찾을 수 없음")

    paths, error = _orphans()
    if paths is None:
        return result(CODE, TITLE, FAILED, f"소유자 없는 파일 검색 실패: {error}")
    if not paths:
        return None

    prefix = "dry-run: " if dry_run else ""
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "업무 소유자를 확인한 뒤 삭제 또는 chown/chgrp 필요(자동 root 귀속 금지): "
        + summarize(paths, limit=10),
    )


"""U-25 world writable 파일 점검 - 업무 필요성 확인 후 조치."""

from fix_common import MANUAL, FAILED, result, command_exists, run_command, summarize


CODE = "U-25"
TITLE = "world writable 파일 점검"


def _world_writable_files():
    code, output, error = run_command(
        ["find", "/", "-xdev", "-type", "f", "-perm", "-0002", "-print"],
        timeout=60,
    )
    if code != 0:
        return None, error or output or f"find exit={code}"
    return [line.strip() for line in output.splitlines() if line.strip()], ""


def fix(dry_run=False):
    if not command_exists("find"):
        return result(CODE, TITLE, FAILED, "find 명령을 찾을 수 없음")

    paths, error = _world_writable_files()
    if paths is None:
        return result(CODE, TITLE, FAILED, f"world writable 검색 실패: {error}")
    if not paths:
        return None

    prefix = "dry-run: " if dry_run else ""
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "공유 목적을 확인한 뒤 chmod o-w 또는 파일 제거 필요(일괄 변경 금지): "
        + summarize(paths, limit=10),
    )


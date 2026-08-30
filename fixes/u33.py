"""U-33 숨겨진 파일 및 디렉터리 - 관리자 분석이 필요한 항목."""

import os

from fix_common import MANUAL, result, command_exists, run_command, summarize


CODE = "U-33"
TITLE = "숨겨진 파일 및 디렉토리 검색 및 제거"
SCAN_ROOTS = (
    "/root", "/home", "/tmp", "/var/tmp", "/dev/shm",
    "/var/lib/open5gs", "/var/lib/mongodb",
)


def _samples():
    if not command_exists("find"):
        return []
    samples = []
    for root in SCAN_ROOTS:
        if not os.path.isdir(root):
            continue
        code, output, _ = run_command(
            [
                "find", root, "-xdev", "-mindepth", "1",
                "(", "-type", "f", "-o", "-type", "d", ")",
                "-name", ".*", "-print", "-quit",
            ],
            timeout=10,
        )
        if code == 0 and output:
            samples.append(output.splitlines()[0])
    return samples


def fix(dry_run=False):
    samples = _samples()
    prefix = "dry-run: " if dry_run else ""
    evidence = summarize(samples, limit=10) if samples else "표본 미발견"
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "정상 dotfile과 악성 은닉 파일을 자동 구분할 수 없음. 소유자·해시·실행 중 "
        "프로세스·패키지 소유 여부를 확인한 뒤 불필요한 항목만 제거; 표본: "
        + evidence,
    )


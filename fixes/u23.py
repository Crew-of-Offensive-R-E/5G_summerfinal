"""U-23 임시 점검 허용 목록 밖 SUID/SGID 제거 조치."""

import os
import stat

from fix_common import (
    FIXED,
    FAILED,
    result,
    backup_file,
    command_exists,
    run_command,
    summarize,
)


CODE = "U-23"
TITLE = "SUID, SGID, Sticky bit 점검"

# 임시 점검 코드와 동일한 허용 목록이다. 목록 밖 정상 패키지 파일도 변경될 수
# 있으므로 이 항목은 VM 스냅샷과 서비스 영향 검증을 전제로 실행한다.
ALLOW = {
    "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp",
    "/usr/lib/openssh/ssh-keysign", "/bin/mount", "/bin/umount", "/bin/su",
}


def _special_files():
    code, output, error = run_command(
        ["find", "/", "-xdev", "-type", "f", "-perm", "/6000", "-print"],
        timeout=120,
    )
    if code != 0:
        return None, error or output or f"find exit={code}"
    return [line.strip() for line in output.splitlines() if line.strip()], ""


def _package_owner(path):
    if not command_exists("dpkg-query"):
        return "패키지 확인 불가"
    code, output, _ = run_command(["dpkg-query", "-S", path], timeout=5)
    return output.splitlines()[0] if code == 0 and output else "패키지 미등록"


def fix(dry_run=False):
    if not command_exists("find"):
        return result(CODE, TITLE, FAILED, "find 명령을 찾을 수 없음")

    found, error = _special_files()
    if found is None:
        return result(CODE, TITLE, FAILED, f"SUID/SGID 검색 실패: {error}")

    # 점검 코드가 실경로가 아닌 출력 문자열을 직접 비교하므로 동일하게 판정한다.
    unexpected = [path for path in found if path not in ALLOW]
    if not unexpected:
        return None

    issues = []
    for path in unexpected:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError as exc:
            return result(CODE, TITLE, FAILED, f"{path} 상태 확인 실패: {exc}")
        issues.append((path, mode, _package_owner(path)))

    changes = [
        f"{path}({mode:04o}->{mode & ~0o6000:04o}, {package})"
        for path, mode, package in issues
    ]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 허용 목록 밖 SUID/SGID 제거 예정: "
            + summarize(changes, limit=10),
        )

    backups = []
    for path, _, _ in issues:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    changed = []
    for path, old_mode, _ in issues:
        try:
            os.chmod(path, old_mode & ~0o6000)
            changed.append((path, old_mode))
        except OSError as exc:
            for changed_path, restore_mode in reversed(changed):
                try:
                    os.chmod(changed_path, restore_mode)
                except OSError:
                    pass
            return result(CODE, TITLE, FAILED, f"{path} 권한 변경 실패, 복원 시도: {exc}")

    remaining, error = _special_files()
    if remaining is None:
        remaining = unexpected
    remaining = [path for path in remaining if path not in ALLOW]
    if remaining:
        for path, restore_mode in reversed(changed):
            try:
                os.chmod(path, restore_mode)
            except OSError:
                pass
        return result(
            CODE,
            TITLE,
            FAILED,
            "SUID/SGID 제거 검증 실패로 권한 복원 시도: "
            + summarize(remaining, limit=10),
        )

    return result(
        CODE,
        TITLE,
        FIXED,
        "허용 목록 밖 SUID/SGID 제거: "
        + summarize(changes, limit=10)
        + "; OS·VMware·인증 기능 재검증 필요"
        + "; 백업: "
        + summarize(backups, limit=10),
    )

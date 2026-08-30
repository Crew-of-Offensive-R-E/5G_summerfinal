"""U-57 FTP root 계정 접근 차단 목록 조치."""

import os

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    is_listening_on_port,
    pgrep_any,
    read_text,
    result,
    set_file_mode,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-57"
TITLE = "Ftpusers 파일 설정"
CHECK_PATHS = (
    "/etc/ftpusers",
    "/etc/ftpd/ftpusers",
    "/etc/vsftpd/ftpusers",
    "/etc/vsftpd.user_list",
    "/etc/vsftpd/user_list",
)
DENY_PATHS = CHECK_PATHS[:3]


def _ftp_active():
    return (
        systemctl_is_active("vsftpd", "proftpd", "pure-ftpd")
        or pgrep_any("vsftpd", "proftpd", "pure-ftpd")
        or is_listening_on_port(21)
    )


def _entries(path):
    return [
        line.strip()
        for line in (read_text(path) or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _restore(path, original, mode):
    errors = []
    if not write_text(path, original):
        errors.append("원본 내용 복구 실패")
    if not set_file_mode(path, mode):
        errors.append("원본 권한 복구 실패")
    return errors


def fix(dry_run=False):
    if not _ftp_active():
        return None
    blocked = [path for path in CHECK_PATHS if "root" in _entries(path)]
    if blocked:
        return None
    existing = [path for path in DENY_PATHS if read_text(path) is not None]
    if not existing:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "실제 FTP 데몬이 사용하는 root 거부 목록 경로를 확인해야 함; "
            "/etc/vsftpd.user_list는 허용 목록일 수 있어 자동 변경 제외",
        )
    path = existing[0]
    original = read_text(path)
    original_mode = os.stat(path).st_mode & 0o777
    separator = "" if not original or original.endswith(("\n", "\r")) else "\n"
    updated = original + separator + "root\n"
    if dry_run:
        return result(CODE, TITLE, FIXED, f"dry-run: {path}에 root 차단 항목 추가 및 0640 설정 예정")
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    backup = backup_file(path)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{path}: 백업 실패로 파일을 변경하지 않음")
    if not write_text(path, updated):
        errors = _restore(path, original, original_mode)
        return result(
            CODE,
            TITLE,
            FAILED,
            f"{path}: 쓰기 실패"
            + (f" | {summarize(errors)}" if errors else " | 원본 복구 완료")
            + f" | 백업: {backup}",
        )
    if not set_file_mode(path, 0o640) or "root" not in _entries(path):
        errors = _restore(path, original, original_mode)
        return result(
            CODE,
            TITLE,
            FAILED,
            "root 차단 항목/권한 재확인 실패"
            + (f" | {summarize(errors)}" if errors else " | 원본 복구 완료")
            + f" | 백업: {backup}",
        )
    return result(CODE, TITLE, FIXED, f"{path}: root 차단 항목 추가, mode=0640 | 백업: {backup}")

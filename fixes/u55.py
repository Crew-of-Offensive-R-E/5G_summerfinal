"""U-55 FTP 계정 로그인 shell 제한 조치."""

import os

from fix_common import FAILED, FIXED, NOLOGIN_SHELLS, backup_file, passwd_user, result, run_command


CODE = "U-55"
TITLE = "FTP 계정 shell 제한"
PASSWD_PATH = "/etc/passwd"
NOLOGIN_PATH = "/usr/sbin/nologin"


def fix(dry_run=False):
    ftp = passwd_user("ftp")
    if ftp is None or ftp["shell"] in NOLOGIN_SHELLS:
        return None
    original_shell = ftp["shell"]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: ftp 계정 shell을 {original_shell}에서 {NOLOGIN_PATH}으로 변경 예정",
        )
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")
    if not os.path.exists(NOLOGIN_PATH):
        return result(CODE, TITLE, FAILED, f"로그인 제한 shell을 찾지 못함: {NOLOGIN_PATH}")

    backup = backup_file(PASSWD_PATH)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{PASSWD_PATH}: 백업 실패로 계정을 변경하지 않음")

    code, out, err = run_command(["usermod", "-s", NOLOGIN_PATH, "ftp"], timeout=15)
    if code != 0:
        return result(
            CODE,
            TITLE,
            FAILED,
            f"ftp 계정 shell 변경 실패({err or out or code}) | 백업: {backup}",
        )

    current = passwd_user("ftp")
    if current and current["shell"] in NOLOGIN_SHELLS:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"ftp 계정 shell: {original_shell} -> {current['shell']} | 백업: {backup}",
        )

    rollback_code, rollback_out, rollback_err = run_command(
        ["usermod", "-s", original_shell, "ftp"], timeout=15
    )
    detail = "조치 후 ftp 계정 shell 재확인 실패"
    if rollback_code == 0:
        detail += f" | 원래 shell({original_shell}) 복구 완료"
    else:
        detail += f" | 원복 실패({rollback_err or rollback_out or rollback_code})"
    detail += f" | 백업: {backup}"
    return result(CODE, TITLE, FAILED, detail)

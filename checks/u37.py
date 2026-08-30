"""U-37 crontab 설정파일 권한 설정 미흡"""
import os

from check_common import GOOD, VULN, result

CODE = "U-37"
TITLE = "crontab 설정파일 권한 설정 미흡"

# 1. 실행 명령어 (root 소유 + 750 이하)
CMD_FILES = ["/usr/bin/crontab", "/usr/bin/at"]

# 2. 설정 파일 (root 소유 + 640 이하)
CONFIG_FILES = [
    "/etc/cron.allow",
    "/etc/cron.deny",
    "/etc/crontab",
    "/etc/at.allow",
    "/etc/at.deny",
]

# 3. cron 관련 디렉터리 (root 소유 + 750 이하)
DIRS = [
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/var/spool/at",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
]


def check():
    issues = []

    # 1. 실행 파일 점검 (소유자 root(0) + 권한 750 이하)
    for path in CMD_FILES:
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
            if st.st_uid != 0 or (st.st_mode & 0o777) > 0o750:
                issues.append(f"{path}(권한/소유자 부적절)")
        except (PermissionError, OSError):
            issues.append(f"{path}(접근 실패)")

    # 2. 설정 파일 점검 (소유자 root(0) + 권한 640 이하)
    for path in CONFIG_FILES:
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
            if st.st_uid != 0 or (st.st_mode & 0o777) > 0o640:
                issues.append(f"{path}(권한/소유자 부적절)")
        except (PermissionError, OSError):
            issues.append(f"{path}(접근 실패)")

    # 3. 디렉터리 점검 (소유자 root(0) + 권한 750 이하)
    for path in DIRS:
        if not os.path.isdir(path):
            continue
        try:
            st = os.stat(path)
            if st.st_uid != 0 or (st.st_mode & 0o777) > 0o750:
                issues.append(f"{path}(권한/소유자 부적절)")
        except (PermissionError, OSError):
            issues.append(f"{path}(접근 실패)")

    if issues:
        return result(CODE, TITLE, VULN, f"취약 항목 발견: {', '.join(issues)}")

    return result(CODE, TITLE, GOOD, "crontab/at 실행 파일, 설정 파일 및 디렉터리 권한/소유자가 양호합니다.")

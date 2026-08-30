"""U-55 FTP 계정 shell 제한"""
from check_common import (
    GOOD,
    VULN,
    result,
    passwd_user,
    NOLOGIN_SHELLS,
)

CODE = "U-55"
TITLE = "FTP 계정 shell 제한"


def check():
    # 1. ftp 계정 존재 여부 확인
    ftp = passwd_user("ftp")
    if ftp is None:
        return result(CODE, TITLE, GOOD, "ftp 계정이 존재하지 않습니다.")

    # 2. ftp 계정의 로그인 쉘 확인 (읽기 전용)
    if ftp["shell"] in NOLOGIN_SHELLS:
        return result(CODE, TITLE, GOOD, f"ftp 계정 쉘이 로그인 제한 값으로 설정되어 있습니다: {ftp['shell']}")

    return result(CODE, TITLE, VULN, f"ftp 계정에 로그인 가능한 쉘이 부여되어 있습니다: {ftp['shell']}")

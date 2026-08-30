"""D-07 root 권한으로 서비스 구동 제한"""
from check_common import GOOD, VULN, NA, result, get_mongod_process_user

CODE = "D-07"
TITLE = "root 권한으로 서비스 구동 제한"


def check():
    proc_user = get_mongod_process_user()
    if proc_user is None:
        return result(CODE, TITLE, NA, "mongod 프로세스 미실행")

    if proc_user == "root":
        return result(CODE, TITLE, VULN,
                      "mongod가 root 권한으로 실행 중")
    return result(CODE, TITLE, GOOD,
                  f"mongod 실행 사용자: {proc_user}")

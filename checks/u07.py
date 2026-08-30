from check_common import MANUAL, result


CODE = "U-07"
TITLE = "불필요한 계정 제거"


def check():
    return result(CODE, TITLE, MANUAL, "lp, uucp, games 등 - 서비스 사용 여부 확인 필요")

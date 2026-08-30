from check_common import MANUAL, result


CODE = "U-28"
TITLE = "접속 IP 및 포트 제한"


def check():
    return result(CODE, TITLE, MANUAL, "방화벽/보안그룹/hosts.allow 등 수동 확인")

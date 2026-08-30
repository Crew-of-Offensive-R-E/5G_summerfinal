from check_common import MANUAL, result


CODE = "U-25"
TITLE = "world writable 파일 점검"


def check():
    return result(CODE, TITLE, MANUAL, "업무 필요성 판단 필요: find / -perm -2 -type f")

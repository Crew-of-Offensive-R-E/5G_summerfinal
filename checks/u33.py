from check_common import MANUAL, result


CODE = "U-33"
TITLE = "숨겨진 파일 및 디렉토리 검색 및 제거"


def check():
    return result(CODE, TITLE, MANUAL, "업무 필요성 판단 필요: find / -name '.*'")

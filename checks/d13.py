"""D-13 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"""
from check_common import NA, result

CODE = "D-13"
TITLE = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"


def check():
    return result(CODE, TITLE, NA,
                  "Windows OS 전용 항목 — MongoDB(Linux) 해당 없음")

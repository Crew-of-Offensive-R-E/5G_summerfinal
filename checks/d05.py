"""D-05 패스워드 재사용에 대한 제약을 설정"""
from check_common import GOOD, VULN, NA, MANUAL, result, read_text, MONGOD_CONF

CODE = "D-05"
TITLE = "패스워드 재사용에 대한 제약을 설정"


def check():
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    return result(CODE, TITLE, MANUAL,
                  "MongoDB는 자체 패스워드 재사용 제한 미지원 — "
                  "[수동 점검 기준] ① 최근 사용한 패스워드 4개 이내 재사용 금지 정책 수립 여부 "
                  "② 패스워드 변경 이력 관리 대장(문서/시스템) 운영 여부")

"""D-03 패스워드의 사용기간 및 복잡도를 기관 정책에 맞도록 설정"""
from check_common import GOOD, VULN, NA, MANUAL, result, read_text, MONGOD_CONF

CODE = "D-03"
TITLE = "패스워드의 사용기간 및 복잡도를 기관 정책에 맞도록 설정"


def check():
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    if "ldap" in text.lower() or "PLAIN" in text:
        return result(CODE, TITLE, MANUAL,
                      "LDAP 연동 감지 — "
                      "[수동 점검 기준] ① 패스워드 8자리 이상, 영문 대/소문자·숫자·특수문자 중 3종 이상 조합 "
                      "② 패스워드 최대 사용기간 90일 이내 "
                      "③ 패스워드 최소 사용기간 1일 이상 (LDAP 서버 정책 확인)")

    return result(CODE, TITLE, MANUAL,
                  "MongoDB는 자체 패스워드 복잡도/만료 정책 미지원 — "
                  "[수동 점검 기준] ① 패스워드 8자리 이상, 영문 대/소문자·숫자·특수문자 중 3종 이상 조합 "
                  "② 패스워드 최대 사용기간 90일 이내 "
                  "③ 패스워드 최소 사용기간 1일 이상")

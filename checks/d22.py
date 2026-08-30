"""D-22 데이터베이스의 자원 제한 기능을 TRUE로 설정"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF

CODE = "D-22"
TITLE = "데이터베이스의 자원 제한 기능을 TRUE로 설정"

DEFAULT_MAX_CONN = 65536


def check(**_kw):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    # net.maxIncomingConnections 설정 확인
    max_conn = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "maxIncomingConnections:" in s:
            try:
                max_conn = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass

    if max_conn is None:
        return result(CODE, TITLE, VULN,
                      f"maxIncomingConnections 미설정 — 기본값({DEFAULT_MAX_CONN}) 사용 중, 명시적 제한 필요")

    if max_conn >= DEFAULT_MAX_CONN:
        return result(CODE, TITLE, VULN,
                      f"maxIncomingConnections: {max_conn} — 기본값 이상으로 제한 효과 없음")

    return result(CODE, TITLE, GOOD,
                  f"maxIncomingConnections: {max_conn} — 접속 수 제한 설정됨")

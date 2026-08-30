"""D-10 원격에서 DB 서버로의 접속 제한"""
from check_common import GOOD, VULN, NA, result, get_bind_ip, read_text, MONGOD_CONF

CODE = "D-10"
TITLE = "원격에서 DB 서버로의 접속 제한"

_OPEN_BINDS = {"0.0.0.0", "::"}


def check():
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    bind_ip = get_bind_ip()

    if bind_ip is None:
        return result(CODE, TITLE, VULN,
                      "bindIp 미설정 — 기본값(모든 인터페이스) 바인딩으로 "
                      "원격 접속 제한 없음")

    addrs = [a.strip() for a in bind_ip.split(",")]
    open_addrs = [a for a in addrs if a in _OPEN_BINDS]

    if open_addrs:
        return result(CODE, TITLE, VULN,
                      f"bindIp: {bind_ip} — 모든 인터페이스에 바인딩되어 "
                      "원격 접속 제한 없음")

    return result(CODE, TITLE, GOOD,
                  f"bindIp: {bind_ip} — 특정 IP로 접속 제한 설정됨")

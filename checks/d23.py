"""D-23 xp_cmdshell 사용 제한"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF

CODE = "D-23"
TITLE = "xp_cmdshell 사용 제한"


def check(**_kw):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    # security.javascriptEnabled 설정 확인
    js_enabled = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "javascriptEnabled:" in s:
            val = s.split(":", 1)[1].strip().strip('"').strip("'").lower()
            js_enabled = val

    if js_enabled is None:
        return result(CODE, TITLE, VULN,
                      "javascriptEnabled 미설정 — 기본값(true)으로 서버 사이드 JS 실행 가능")

    if js_enabled in ("true", "1", "yes"):
        return result(CODE, TITLE, VULN,
                      "javascriptEnabled: true — 서버 사이드 JavaScript 실행 허용됨")

    return result(CODE, TITLE, GOOD,
                  "javascriptEnabled: false — 서버 사이드 JavaScript 실행 차단됨")

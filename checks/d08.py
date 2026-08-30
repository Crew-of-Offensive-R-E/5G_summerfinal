"""D-08 안전한 암호화 알고리즘 사용"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF, mongo_eval

CODE = "D-08"
TITLE = "안전한 암호화 알고리즘 사용"

_SAFE_MECHANISMS = {"SCRAM-SHA-256", "MONGODB-X509"}
_WEAK_MECHANISMS = {"MONGODB-CR", "SCRAM-SHA-1"}


def check(user=None, password=None):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    # 설정 파일에서 authenticationMechanisms 확인
    conf_mechanism = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "authenticationMechanisms" in s:
            conf_mechanism = s.split(":", 1)[1].strip().strip('"').strip("'")

    # 서버에서 실제 인증 메커니즘 조회
    js = "EJSON.stringify(db.adminCommand({getParameter: 1, authenticationMechanisms: 1}))"
    code, out, _ = mongo_eval(js, user=user, password=password)
    server_mechanisms = None
    if code == 0 and "authenticationMechanisms" in out:
        import json
        try:
            data = json.loads(out)
            server_mechanisms = data.get("authenticationMechanisms", [])
        except (json.JSONDecodeError, ValueError):
            pass

    # 서버 조회 성공 시 — 실제 메커니즘 기준 판정
    if server_mechanisms is not None:
        mechs = set(server_mechanisms)
        weak = mechs & _WEAK_MECHANISMS
        safe = mechs & _SAFE_MECHANISMS
        if weak and not safe:
            return result(CODE, TITLE, VULN,
                          f"취약한 인증 메커니즘만 사용: {', '.join(sorted(weak))}")
        if weak:
            return result(CODE, TITLE, VULN,
                          f"인증 메커니즘: {', '.join(sorted(mechs))} "
                          f"— 취약 메커니즘 포함({', '.join(sorted(weak))})")
        return result(CODE, TITLE, GOOD,
                      f"인증 메커니즘: {', '.join(sorted(mechs))}")

    # 서버 조회 실패 시 — 설정 파일 기준 판정
    if conf_mechanism:
        upper = conf_mechanism.upper()
        if "SCRAM-SHA-256" in upper or "X509" in upper:
            return result(CODE, TITLE, GOOD,
                          f"설정 파일 인증 메커니즘: {conf_mechanism}")
        if "MONGODB-CR" in upper or "SCRAM-SHA-1" in upper:
            return result(CODE, TITLE, VULN,
                          f"취약한 인증 메커니즘: {conf_mechanism}")

    return result(CODE, TITLE, GOOD,
                  "인증 메커니즘 기본값 SCRAM-SHA-256 (MongoDB 4.0+)")

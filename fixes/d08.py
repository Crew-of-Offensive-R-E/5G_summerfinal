"""D-08 안전한 암호화 알고리즘 사용(SCRAM-SHA-256 이상) 조치

판단 기준(확인팀 5G_Check_Tool checks/d08.py 기준): 서버에서 실제 조회한
authenticationMechanisms(또는 조회 불가 시 mongod.conf의 authenticationMechanisms
설정값)에 SCRAM-SHA-256이나 MONGODB-X509가 있으면 양호, MONGODB-CR/SCRAM-SHA-1
같은 취약 메커니즘이 있으면 취약. 서버 조회가 자격증명 없이 실패하면 확인팀
check()도 설정 파일 값으로 대체 판정하므로, 이 조치도 같은 순서(서버 조회 →
실패 시 설정 파일)로 "이미 양호"를 판단한다 — 자격증명 없이도 이미 양호인
경우는 정상적으로 감지된다. 실제로 취약(SCRAM-SHA-1 등)을 제거하는 조치는
서버 조회로 계정별 잠금 위험까지 확인해야 하므로 자격증명이 필요하다.

MONGODB-X509는 해시 알고리즘이 아니라 인증서 기반 메커니즘이므로 자동으로
제거하지 않는다.
"""

import time

from fix_common import (
    FIXED, FAILED, MANUAL, result,
    backup_file, read_text, write_text, set_conf_scalar,
    mongo_eval_json, systemctl_is_active, run_command,
    MONGOD_CONF,
)

CODE = "D-08"
TITLE = "안전한 암호화 알고리즘 사용"
WEAK = "SCRAM-SHA-1"
TARGET = "SCRAM-SHA-256"


def _get_mechanisms(user, password):
    js = "EJSON.stringify(db.adminCommand({getParameter:1, authenticationMechanisms:1}))"
    data = mongo_eval_json(js, user, password)
    if data is None:
        return None
    return data.get("authenticationMechanisms")


def _get_users_mechanisms(user, password):
    js = "EJSON.stringify(db.adminCommand({usersInfo:{forAllDBs:true}}))"
    data = mongo_eval_json(js, user, password)
    if data is None:
        return None
    return data.get("users", [])


def _wait_mechanisms(user, password, attempts=8, interval=1.5):
    for _ in range(attempts):
        mechs = _get_mechanisms(user, password)
        if mechs is not None:
            return mechs
        time.sleep(interval)
    return None


def _config_mechanism_value():
    """mongod.conf에서 authenticationMechanisms 값을 문자열로 반환(확인팀 폴백 로직과 동일)."""
    text = read_text(MONGOD_CONF)
    if text is None:
        return None
    value = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "authenticationMechanisms" in s and ":" in s:
            value = s.split(":", 1)[1].strip().strip('"').strip("'")
    return value


def fix(user=None, password=None, dry_run=False):
    if not systemctl_is_active("mongod"):
        return result(CODE, TITLE, MANUAL, "mongod 서비스가 비활성 상태 — 자동 조치 대상 아님(수동 확인 필요)")

    mechanisms = _get_mechanisms(user, password)

    if mechanisms is None:
        # 확인팀 check()와 동일하게 서버 조회 실패 시 설정 파일 값으로 "이미 양호"만 판단한다.
        # (실제 제거 조치는 계정별 잠금 위험을 확인해야 하므로 자격증명 없이는 하지 않는다.)
        conf_value = _config_mechanism_value()
        if conf_value is None:
            return None  # 확인팀 기본값 가정과 동일: 설정 없음 → 기본값 SCRAM-SHA-256으로 양호
        upper = conf_value.upper()
        if "SCRAM-SHA-256" in upper or "X509" in upper:
            return None  # 이미 양호 (설정 파일 기준)
        if "SCRAM-SHA-1" in upper or "MONGODB-CR" in upper:
            detail = ("인증 필요(-u + --ask-password 또는 MONGO_ADMIN_USER/PASSWORD)"
                      if not (user and password) else "제공된 자격증명으로 서버 조회 실패")
            return result(CODE, TITLE, MANUAL,
                          f"설정 파일 기준 취약한 메커니즘 포함(authenticationMechanisms: {conf_value}) — "
                          f"{detail}, 계정별 잠금 위험 확인 필요해 자동 조치 보류")
        return result(CODE, TITLE, MANUAL,
                      f"authenticationMechanisms 값을 판단할 수 없음(설정: {conf_value}) — 수동 확인 필요")

    if WEAK not in mechanisms:
        return None  # 이미 양호 (MONGODB-X509 존재 여부와 무관)

    users = _get_users_mechanisms(user, password)
    if users is None:
        return result(CODE, TITLE, MANUAL,
                      f"서버 authenticationMechanisms={mechanisms}에 {WEAK} 포함되어 취약하나, "
                      "계정별 mechanisms를 확인할 수 없어 전용 전환 시 잠길 계정이 있는지 판단 불가 — 자동 조치 보류")

    at_risk = [
        f"{u.get('user')}@{u.get('db')}" for u in users
        if u.get("mechanisms") and TARGET not in u.get("mechanisms", [])
    ]
    if at_risk:
        return result(CODE, TITLE, MANUAL,
                      f"서버 authenticationMechanisms={mechanisms}에 {WEAK} 포함되어 취약하나, "
                      f"다음 계정이 {TARGET} 자격증명이 없어 전환 시 잠길 위험: {at_risk} — "
                      "해당 계정 비밀번호 재설정 후 재시도 필요")

    target_mechs = [m for m in mechanisms if m != WEAK]
    if TARGET not in target_mechs:
        target_mechs.append(TARGET)
    target_value = ",".join(target_mechs)

    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 읽기 실패")

    if dry_run:
        return result(CODE, TITLE, FIXED,
                      f"dry-run: 조치 전 authenticationMechanisms={mechanisms} → "
                      f"setParameter.authenticationMechanisms에서 {WEAK}만 제거, 목표값 '{target_value}' 적용 예정")

    backup_path = backup_file(MONGOD_CONF)
    if backup_path is None:
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 백업 실패로 조치를 건너뜀")

    new_text = set_conf_scalar(text, "setParameter", "authenticationMechanisms", target_value)
    if not write_text(MONGOD_CONF, new_text):
        return result(CODE, TITLE, FAILED, f"{MONGOD_CONF} 쓰기 실패(권한 확인)")

    run_command(["systemctl", "daemon-reload"])
    restart_code, _, restart_err = run_command(["systemctl", "restart", "mongod"], timeout=30)

    def _rollback(reason):
        run_command(["cp", "-a", backup_path, MONGOD_CONF])
        run_command(["systemctl", "restart", "mongod"], timeout=30)
        return result(CODE, TITLE, FAILED,
                      f"조치 전 authenticationMechanisms={mechanisms}, 목표값 '{target_value}'(백업: {backup_path}) "
                      f"적용 시도, {reason} → 백업에서 롤백")

    if restart_code != 0:
        return _rollback(f"mongod 재시작 실패({restart_err})")

    after = _wait_mechanisms(user, password)
    if after is None:
        return _rollback("재시작 후 준비 대기 중 authenticationMechanisms 재확인 실패")

    if WEAK in after or TARGET not in after:
        return _rollback(f"재검증 실패(조치 후 authenticationMechanisms={after})")

    return result(CODE, TITLE, FIXED,
                  f"조치 전 authenticationMechanisms={mechanisms}. {MONGOD_CONF}의 setParameter."
                  f"authenticationMechanisms에서 {WEAK}만 제거하고 '{target_value}'로 설정(백업: {backup_path}), "
                  f"재시작 후 authenticationMechanisms={after} 재검증 완료")

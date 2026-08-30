"""D-26 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"""
from check_common import VULN, NA, MANUAL, result, read_text, MONGOD_CONF

CODE = "D-26"
TITLE = "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"


def check():
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    has_audit_log = False
    audit_dest = ""
    has_system_log = False
    has_profiling = False

    in_audit = False
    in_syslog = False
    in_profiling = False

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue

        # 섹션 진입 감지
        if s == "auditLog:" or s.startswith("auditLog:"):
            in_audit = True
            has_audit_log = True
            continue
        if s == "systemLog:" or s.startswith("systemLog:"):
            in_syslog = True
            continue
        if s == "operationProfiling:" or s.startswith("operationProfiling:"):
            in_profiling = True
            has_profiling = True
            continue

        # 새 최상위 섹션 시작 시 이전 섹션 종료
        if s and not line.startswith((" ", "\t")):
            in_audit = False
            in_syslog = False
            in_profiling = False

        # auditLog 세부
        if in_audit and s.startswith("destination:"):
            audit_dest = s.split(":", 1)[1].strip()

        # systemLog 세부
        if in_syslog and s.startswith("path:"):
            has_system_log = True

    # 판정
    if has_audit_log:
        detail = "감사 설정 존재"
        if audit_dest:
            detail += f" (destination={audit_dest})"
        detail += (" — [수동 점검 기준] ① DB 접속/로그아웃, 계정 생성/삭제/권한 변경 로그 기록 여부 "
                   "② 감사 로그 최소 6개월 이상 보관 여부 "
                   "③ 감사 로그 무단 삭제/변조 방지 대책 수립 여부")
        return result(CODE, TITLE, MANUAL, detail)

    if has_system_log:
        detail = "기본 로깅만 설정"
        if has_profiling:
            detail += " + operationProfiling 활성"
        detail += (" — [수동 점검 기준] ① DB 접속/로그아웃, 계정 생성/삭제/권한 변경 로그 기록 여부 "
                   "② 감사 로그 최소 6개월 이상 보관 여부 "
                   "③ 감사 로그 무단 삭제/변조 방지 대책 수립 여부")
        return result(CODE, TITLE, MANUAL, detail)

    return result(CODE, TITLE, VULN,
                  "systemLog/auditLog 모두 미설정 — 감사 기록 없음")

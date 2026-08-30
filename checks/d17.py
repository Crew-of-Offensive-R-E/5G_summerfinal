"""D-17 Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF, file_owner_mode_ok, summarize
import os

CODE = "D-17"
TITLE = "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"

VALID_OWNERS = ("mongod", "mongodb")


def _parse_yaml_value(text, section, key):
    """간이 YAML 파서: section 하위의 key 값을 반환한다."""
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_section = stripped == f"{section}:"
            continue
        if in_section and stripped.startswith(f"{key}:"):
            return stripped.split(":", 1)[1].strip().strip("'\"")
    return None


def check():
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    findings = []
    audit_configured = False

    # 1) Enterprise auditLog 확인
    audit_dest = _parse_yaml_value(text, "auditLog", "destination")
    audit_path = _parse_yaml_value(text, "auditLog", "path")

    if audit_dest:
        audit_configured = True
        if audit_dest == "file" and audit_path and os.path.isfile(audit_path):
            ok = any(
                file_owner_mode_ok(audit_path, owner=o, max_mode=0o640)[0]
                for o in VALID_OWNERS
            )
            if not ok:
                _, desc = file_owner_mode_ok(audit_path, owner="mongod", max_mode=0o640)
                findings.append(f"auditLog({audit_path}): {desc}")

    # 2) Community Edition: operationProfiling / profile 확인
    if not audit_configured:
        if "operationProfiling" in text or "profile" in text:
            audit_configured = True

    # 3) systemLog.path 로그 파일 권한 확인
    syslog_path = _parse_yaml_value(text, "systemLog", "path")
    if syslog_path and os.path.isfile(syslog_path):
        ok = any(
            file_owner_mode_ok(syslog_path, owner=o, max_mode=0o640)[0]
            for o in VALID_OWNERS
        )
        if not ok:
            _, desc = file_owner_mode_ok(syslog_path, owner="mongod", max_mode=0o640)
            findings.append(f"systemLog({syslog_path}): {desc}")

    # 판정
    if not audit_configured:
        return result(CODE, TITLE, VULN, "감사 기능 미설정")

    if findings:
        return result(CODE, TITLE, VULN, summarize(findings))
    return result(CODE, TITLE, GOOD,
                  "감사 로그 설정 확인 — 로그 파일 접근 권한 적절")

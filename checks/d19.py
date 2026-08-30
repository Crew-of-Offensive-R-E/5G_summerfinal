"""D-19 OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"""
from check_common import GOOD, VULN, NA, result, read_text, MONGOD_CONF
import os

CODE = "D-19"
TITLE = "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"


def _parse_keyfile_path(text):
    """mongod.conf에서 security.keyFile 경로를 추출한다."""
    in_security = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_security = stripped == "security:"
            continue
        if in_security and stripped.startswith("keyFile:"):
            path = stripped.split(":", 1)[1].strip().strip("'\"")
            if path:
                return path
    return None


def _has_tls_config(text):
    """mongod.conf에 TLS/SSL 인증서 설정이 있는지 확인한다."""
    lower = text.lower()
    for keyword in ("certificatekeyfile:", "tlscertificatekeyfile:",
                    "sslpemkeyfile:", "mode: requiretls",
                    "mode: requiressl", "mode: preferssl"):
        if keyword in lower:
            return True
    return False


def _is_replicaset(text):
    """mongod.conf에 replication.replSetName이 설정되어 있는지 확인한다."""
    in_replication = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            in_replication = stripped == "replication:"
            continue
        if in_replication and stripped.startswith("replSetName:"):
            val = stripped.split(":", 1)[1].strip().strip("'\"")
            if val:
                return True
    return False


def check(**_kw):
    text = read_text(MONGOD_CONF)
    if text is None:
        return result(CODE, TITLE, NA, "mongod.conf 없음(미설치)")

    # 단일 노드(standalone)는 내부 인증 해당 없음
    if not _is_replicaset(text):
        return result(CODE, TITLE, NA,
                      "단일 노드(레플리카셋 미구성) — 내부 인증 해당 없음")

    findings = []

    # 1) keyFile 설정 확인 (레플리카셋/샤드 내부 인증)
    keyfile = _parse_keyfile_path(text)
    has_keyfile = keyfile and os.path.isfile(keyfile)

    # 2) X.509 인증서 설정 확인
    has_tls = _has_tls_config(text)

    if has_keyfile:
        findings.append(f"keyFile: {keyfile}")
    if has_tls:
        findings.append("TLS/X.509 인증서 설정 확인")

    if not has_keyfile and not has_tls:
        return result(CODE, TITLE, VULN,
                      "내부 인증 미설정 — keyFile 또는 X.509 인증서 설정 필요")

    return result(CODE, TITLE, GOOD,
                  f"내부 인증 설정됨 — {', '.join(findings)}")

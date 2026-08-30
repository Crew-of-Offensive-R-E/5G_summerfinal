"""U-54 평문 FTP 서비스 비활성화 수동 조치 안내."""

from fix_common import MANUAL, is_listening_on_port, pgrep_any, result, summarize, systemctl_is_active


CODE = "U-54"
TITLE = "암호화되지 않는 FTP 서비스 비활성화"


def _active_evidence():
    evidence = []
    for name in ("vsftpd", "proftpd", "pure-ftpd"):
        if systemctl_is_active(name, f"{name}.service"):
            evidence.append(f"systemd:{name}")
        if pgrep_any(name):
            evidence.append(f"process:{name}")
    if is_listening_on_port(21):
        evidence.append("port:21/tcp")
    return evidence


def fix(dry_run=False):
    active = _active_evidence()
    if not active:
        return None
    return result(
        CODE,
        TITLE,
        MANUAL,
        "FTP 사용 중단·SFTP/FTPS 전환 및 영향도 확인 후 서비스 비활성화 필요 - "
        + summarize(active),
    )

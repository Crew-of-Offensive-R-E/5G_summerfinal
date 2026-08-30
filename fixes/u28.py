"""U-28 접속 IP 및 포트 제한 - 네트워크 정책 입력이 필요한 항목."""

from fix_common import MANUAL, result, command_exists, run_command


CODE = "U-28"
TITLE = "접속 IP 및 포트 제한"


def _firewall_state():
    if command_exists("ufw"):
        code, output, error = run_command(["ufw", "status", "verbose"], timeout=10)
        if code == 0:
            first = output.splitlines()[0] if output else "상태 출력 없음"
            return "UFW " + first
        return "UFW 확인 실패: " + (error or output or f"exit={code}")
    if command_exists("iptables"):
        code, output, error = run_command(["iptables", "-S", "INPUT"], timeout=10)
        if code == 0:
            return f"iptables INPUT 규칙 {len(output.splitlines())}개"
        return "iptables 확인 실패: " + (error or output or f"exit={code}")
    return "호스트 방화벽 도구 미확인"


def fix(dry_run=False):
    prefix = "dry-run: " if dry_run else ""
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "관리자 SSH IP, gNB N2/N3 주소, 분리형 UPF·NF 통신망을 확정한 뒤 "
        "UFW/보안그룹에 출발지·프로토콜·포트별 허용 규칙 적용 필요; "
        + _firewall_state(),
    )


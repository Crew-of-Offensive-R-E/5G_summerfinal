"""U-65 NTP 및 시각 동기화 설정"""
import re

from check_common import (
    GOOD,
    VULN,
    command_exists,
    read_text,
    result,
    run_command,
    systemctl_is_active,
)

CODE = "U-65"
TITLE = "NTP 및 시각 동기화 설정"
TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"


def _has_ntp_server_config():
    configs = [
        read_text("/etc/chrony/chrony.conf") or "",
        read_text(TIMESYNCD_CONF) or "",
        read_text("/etc/ntp.conf") or "",
    ]
    return any(re.search(r"(?im)^\s*(server|pool|NTP=)\s*\S+", text) for text in configs)


def _process_contains(name):
    if not command_exists("ps"):
        return False
    rc, stdout, _ = run_command(["ps", "ax"], timeout=3)
    return rc == 0 and name in stdout


def _ntp_service_running():
    return (
        systemctl_is_active("chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd")
        or _process_contains("chronyd")
        or _process_contains("ntpd")
        or _process_contains("systemd-timesyncd")
    )


def _timedatectl_synchronized():
    if not command_exists("timedatectl"):
        return False

    rc, stdout, _ = run_command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    return rc == 0 and stdout.strip().lower() == "yes"


def check():
    running = _ntp_service_running()
    has_config = _has_ntp_server_config()
    synchronized = _timedatectl_synchronized()

    if (running or synchronized) and has_config:
        return result(
            CODE,
            TITLE,
            GOOD,
            "NTP 서비스 실행 및 외부 시각 동기화 서버 설정이 정상적으로 확인되었습니다.",
        )

    detail = []
    if not has_config:
        detail.append("NTP 동기화 서버 설정 미비(/etc/chrony/chrony.conf, timesyncd.conf 등)")
    if not running:
        detail.append("NTP 관련 서비스(chrony, systemd-timesyncd, ntp 등) 미실행")
    if not synchronized:
        detail.append("timedatectl 동기화 상태(NTPSynchronized=yes) 미동기화")

    return result(
        CODE,
        TITLE,
        VULN,
        "시각 동기화 설정 미흡: " + ", ".join(detail),
    )

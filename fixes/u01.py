"""U-01 root 계정 원격 접속 제한 조치."""

import re
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    read_text,
    backup_file,
    write_text,
    command_exists,
    run_command,
    systemctl_is_active,
    systemctl_restart,
    is_listening_on_port,
    summarize,
)


CODE = "U-01"
TITLE = "root 계정 원격 접속 제한"
TARGET = "/etc/ssh/sshd_config"
DROPIN_DIR = Path("/etc/ssh/sshd_config.d")


def _config_paths():
    paths = [TARGET]
    if DROPIN_DIR.exists():
        paths.extend(str(path) for path in sorted(DROPIN_DIR.glob("*.conf")))
    return paths


def _active_values():
    values = []
    for path in _config_paths():
        text = read_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"(?i)^PermitRootLogin\s+(\S+)", stripped)
            if match:
                values.append(match.group(1).lower())
    return values


def _effective_root_blocked():
    if not command_exists("sshd"):
        return False
    code, output, _ = run_command(
        [
            "sshd", "-T", "-f", TARGET, "-C",
            "user=root,host=localhost,addr=127.0.0.1",
        ],
        timeout=10,
    )
    if code != 0:
        return False
    return any(
        line.strip().lower() == "permitrootlogin no"
        for line in output.splitlines()
    )


def _secure_text(text, ensure_setting=False):
    """활성 PermitRootLogin 값을 모두 no로 통일한다."""
    pattern = re.compile(r"^\s*PermitRootLogin(?:\s+|=).*$", re.IGNORECASE)
    lines = []
    matched = False
    for line in text.splitlines():
        if pattern.match(line):
            lines.append("PermitRootLogin no")
            matched = True
        else:
            lines.append(line)
    if ensure_setting and not matched:
        lines.insert(0, "PermitRootLogin no")
    return "\n".join(lines) + "\n"


def _rollback(originals):
    for path, text in originals.items():
        write_text(path, text)


def fix(dry_run=False):
    ssh_in_use = systemctl_is_active("ssh", "sshd") or is_listening_on_port(22)
    telnet_in_use = is_listening_on_port(23)

    if not ssh_in_use and not telnet_in_use:
        return None
    if not ssh_in_use and telnet_in_use:
        return result(
            CODE, TITLE, MANUAL,
            "Telnet(23번 포트) 서비스 방식 확인 후 비활성화 필요",
        )

    main_text = read_text(TARGET)
    if main_text is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일을 읽을 수 없음")

    values = _active_values()
    if _effective_root_blocked() and values and all(v == "no" for v in values):
        if telnet_in_use:
            return result(CODE, TITLE, MANUAL, "SSH는 양호하나 Telnet 비활성화 필요")
        return None

    originals = {}
    changes = {}
    for path in _config_paths():
        text = read_text(path)
        if text is None:
            return result(CODE, TITLE, FAILED, f"설정 파일 읽기 실패: {path}")
        new_text = _secure_text(text, ensure_setting=(path == TARGET))
        if new_text != text:
            originals[path] = text
            changes[path] = new_text

    if dry_run:
        status = MANUAL if telnet_in_use else FIXED
        detail = "dry-run: PermitRootLogin no 적용 예정"
        if telnet_in_use:
            detail += ", Telnet은 별도 비활성화 필요"
        return result(CODE, TITLE, status, detail)

    backups = []
    for path in changes:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    written = {}
    for path, new_text in changes.items():
        if not write_text(path, new_text):
            _rollback(written)
            return result(CODE, TITLE, FAILED, f"쓰기 실패로 원본 복원: {path}")
        written[path] = originals[path]

    code, _, error = run_command(["sshd", "-t", "-f", TARGET], timeout=10)
    if code != 0 or not _effective_root_blocked() or any(v != "no" for v in _active_values()):
        _rollback(originals)
        detail = error or "PermitRootLogin no 실제 적용 확인 실패"
        return result(CODE, TITLE, FAILED, f"원본 복원: {detail}")

    service = "ssh" if systemctl_is_active("ssh") else "sshd"
    restarted, restart_detail = systemctl_restart(service)
    if not restarted:
        _rollback(originals)
        systemctl_restart(service)
        return result(
            CODE, TITLE, FAILED,
            f"SSH 재시작 실패로 원본 복원: {restart_detail}",
        )

    if telnet_in_use:
        return result(
            CODE, TITLE, MANUAL,
            "SSH root 직접 접속은 차단했으나 Telnet 비활성화 필요; "
            f"백업: {summarize(backups)}",
        )
    return result(
        CODE, TITLE, FIXED,
        f"PermitRootLogin no 적용 및 {service} 재시작; 백업: {summarize(backups)}",
    )


"""U-53 FTP 서비스 배너 정보 노출 제한 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    command_exists,
    is_listening_on_port,
    pgrep_any,
    read_text,
    result,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)

CODE = "U-53"
TITLE = "FTP 서비스 정보 노출 제한"
VSFTPD_FILES = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
PROFTPD_FILES = ("/etc/proftpd/proftpd.conf", "/etc/proftpd.conf")


def _active_services():
    active = set()
    for name in ("vsftpd", "proftpd", "pure-ftpd"):
        if systemctl_is_active(name, f"{name}.service") or pgrep_any(name):
            active.add(name)
    return active


def _existing(paths):
    return [path for path in paths if read_text(path) is not None]


def _evidence():
    safe, weak = [], []
    for path in VSFTPD_FILES:
        for line in (read_text(path) or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "ftpd_banner" not in stripped:
                continue
            value = stripped.split("=", 1)[-1].strip().strip("'\"")
            if value and not re.search(
                r"(vsftp|proftp|ftp\s*server|version|[0-9]+\.[0-9]+)", value, re.I
            ):
                safe.append(f"{path}:ftpd_banner")
            else:
                weak.append(f"{path}:ftpd_banner={value or 'empty'}")
    for path in PROFTPD_FILES:
        for line in (read_text(path) or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or not stripped.lower().startswith("serverident"):
                continue
            if re.search(r"\boff\b", stripped, re.I) or not re.search(
                r"(proftp|ftp\s*server|version|[0-9]+\.[0-9]+)", stripped, re.I
            ):
                safe.append(f"{path}:ServerIdent")
            else:
                weak.append(f"{path}:{stripped}")
    return safe, weak


def _replace_or_append(content, pattern, line):
    regex = re.compile(pattern, re.IGNORECASE)
    output, replaced = [], False
    for old_line in content.splitlines(keepends=True):
        if regex.search(old_line):
            if not replaced:
                newline = "\r\n" if old_line.endswith("\r\n") else "\n"
                output.append(line + newline)
                replaced = True
            continue
        output.append(old_line)
    if not replaced:
        separator = "" if not content or content.endswith(("\n", "\r")) else "\n"
        output.append(separator + line + "\n")
    return "".join(output)


def _plan_changes(active):
    changes = []
    for path in _existing(VSFTPD_FILES):
        original = read_text(path)
        has_directive = any(
            re.search(r"^\s*(?!#).*?ftpd_banner\s*=", line, re.I)
            for line in original.splitlines()
        )
        if "vsftpd" not in active and not has_directive:
            continue
        updated = _replace_or_append(
            original, r"^\s*(?!#).*?ftpd_banner\s*=", "ftpd_banner=Authorized access only"
        )
        if updated != original:
            changes.append({"path": path, "original": original, "updated": updated, "service": "vsftpd"})
    for path in _existing(PROFTPD_FILES):
        original = read_text(path)
        has_directive = any(
            re.search(r"^\s*(?!#)\s*ServerIdent\b", line, re.I)
            for line in original.splitlines()
        )
        if "proftpd" not in active and not has_directive:
            continue
        updated = _replace_or_append(original, r"^\s*(?!#)\s*ServerIdent\b", "ServerIdent off")
        if updated != original:
            changes.append({"path": path, "original": original, "updated": updated, "service": "proftpd"})
    return changes


def _restore(changes):
    return [f"{c['path']}: 원본 복구 실패" for c in changes if not write_text(c["path"], c["original"])]


def _restart(service):
    if not systemctl_is_active(service, f"{service}.service"):
        return None
    code, out, err = run_command(["systemctl", "restart", service], timeout=20)
    return None if code == 0 else f"{service}: 재시작 실패({err or out or code})"


def _validate_proftpd(changes):
    paths = [c["path"] for c in changes if c["service"] == "proftpd"]
    if not paths or not command_exists("proftpd"):
        return None
    code, out, err = run_command(["proftpd", "-t", "-c", paths[0]], timeout=20)
    return None if code == 0 else f"ProFTPD 설정 검증 실패({err or out or code})"


def _failure(message, written, services, backups):
    errors = _restore(written)
    for service in services:
        error = _restart(service)
        if error:
            errors.append(f"원복 후 {error}")
    detail = message + " | " + ("원본 복구 완료" if not errors else summarize(errors))
    if backups:
        detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FAILED, detail)


def fix(dry_run=False):
    active = _active_services()
    port_active = is_listening_on_port(21)
    if not active and not port_active:
        return None
    safe, weak = _evidence()
    if not weak and safe:
        return None
    if "pure-ftpd" in active or (port_active and not active):
        return result(
            CODE, TITLE, MANUAL,
            "Pure-FTPd 또는 21번 포트 관리 주체의 배너 정책 확인 필요 - "
            + summarize(sorted(active) or ["port:21"]),
        )
    if "vsftpd" in active and not _existing(VSFTPD_FILES):
        return result(CODE, TITLE, MANUAL, "vsftpd 활성 상태이나 실제 설정 파일을 찾지 못함")
    if "proftpd" in active and not _existing(PROFTPD_FILES):
        return result(CODE, TITLE, MANUAL, "ProFTPD 활성 상태이나 실제 설정 파일을 찾지 못함")

    changes = _plan_changes(active)
    if not changes:
        return result(CODE, TITLE, FAILED, "FTP 배너 조치 대상을 결정하지 못함")
    if dry_run:
        return result(
            CODE, TITLE, FIXED,
            "dry-run: FTP 배너 일반 경고 문구/비노출 설정 예정 - "
            + summarize([c["path"] for c in changes]),
        )
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    backups = []
    for change in changes:
        backup = backup_file(change["path"])
        if backup is None:
            return result(
                CODE, TITLE, FAILED,
                f"{change['path']}: 백업 실패로 파일을 변경하지 않음"
                + (f" | 완료된 백업: {summarize(backups)}" if backups else ""),
            )
        backups.append(backup)

    written = []
    for change in changes:
        if not write_text(change["path"], change["updated"]):
            return _failure(f"{change['path']}: 설정 쓰기 실패", written, active, backups)
        written.append(change)
    error = _validate_proftpd(written)
    if error:
        return _failure(error, written, active, backups)
    for service in sorted(active):
        error = _restart(service)
        if error:
            return _failure(error, written, active, backups)

    safe_after, weak_after = _evidence()
    if weak_after or not safe_after:
        return _failure(
            "조치 후 FTP 배너 재점검 실패: " + summarize(weak_after or ["안전 설정 없음"]),
            written, active, backups,
        )
    return result(
        CODE, TITLE, FIXED,
        "FTP 배너 정보 노출 제한 완료: " + summarize([c["path"] for c in changes])
        + f" | 백업: {summarize(backups)}",
    )

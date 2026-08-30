"""U-62 로그인 경고 메시지 및 SSH Banner 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    command_exists,
    read_text,
    result,
    restore_backups,
    run_command,
    safe_path,
    set_file_mode,
    set_file_owner,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-62"
TITLE = "로그인 시 경고 메시지 설정"
ISSUE = "/etc/issue"
ISSUE_NET = "/etc/issue.net"
MOTD = "/etc/motd"
SSHD_CONFIG = "/etc/ssh/sshd_config"
WARNING = "Authorized users only. All activities may be monitored and reported."
DEFAULT_MARKERS = ("\\n", "\\l", "Ubuntu", "Debian", "GNU/Linux", "Kernel")


def _custom_warning_path():
    for path in (ISSUE_NET, ISSUE, MOTD):
        text = (read_text(path) or "").strip()
        if len(text) >= 20 and not any(marker in text for marker in DEFAULT_MARKERS):
            return path
    return None


def _ssh_banner_path():
    sshd = read_text(SSHD_CONFIG)
    if sshd is None:
        return None
    matches = re.findall(r"(?im)^\s*Banner\s+(\S+)", sshd)
    return next((value for value in reversed(matches) if value.lower() != "none"), None)


def _replace_banner(content, path):
    pattern = re.compile(r"(?im)^\s*#?\s*Banner\s+\S+\s*$")
    lines = content.splitlines(keepends=True)
    output, replaced = [], False
    for line in lines:
        if pattern.match(line.rstrip("\r\n")):
            if not replaced:
                newline = "\r\n" if line.endswith("\r\n") else "\n"
                output.append(f"Banner {path}{newline}")
                replaced = True
            continue
        output.append(line)
    if not replaced:
        separator = "" if not content or content.endswith(("\n", "\r")) else "\n"
        output.append(f"{separator}Banner {path}\n")
    return "".join(output)


def _rollback(backups, created_paths, unit=None):
    errors = restore_backups(backups)
    for path in reversed(created_paths):
        if not os.path.exists(path):
            continue
        try:
            if not safe_path(path, must_exist=True):
                errors.append(f"{path}: 안전하지 않은 생성 경로로 삭제 거부")
            else:
                os.unlink(path)
        except OSError as exc:
            errors.append(f"{path}: 생성 파일 삭제 실패({exc})")
    if unit:
        code, out, err = run_command(["systemctl", "reload", unit], timeout=20)
        if code != 0:
            errors.append(f"원복 후 {unit} reload 실패({err or out or code})")
    return errors


def _reload_ssh():
    for unit in ("ssh", "sshd"):
        if not systemctl_is_active(unit, f"{unit}.service"):
            continue
        code, out, err = run_command(["systemctl", "reload", unit], timeout=20)
        if code != 0:
            return unit, f"{unit}: reload 실패({err or out or code})"
        return unit, None
    return None, None


def _failure(message, backups, created_paths, unit=None):
    errors = _rollback(backups, created_paths, unit)
    detail = message + " | " + ("원본 복구 완료" if not errors else summarize(errors))
    if backups:
        detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FAILED, detail)


def fix(dry_run=False):
    custom_path = _custom_warning_path()
    sshd = read_text(SSHD_CONFIG)
    banner_path = _ssh_banner_path()
    if custom_path and (sshd is None or banner_path == custom_path):
        return None

    changes = []
    if custom_path is None:
        original = read_text(ISSUE_NET)
        changes.append({"path": ISSUE_NET, "original": original, "updated": WARNING + "\n"})
        custom_path = ISSUE_NET
    if sshd is not None and banner_path != custom_path:
        changes.append({"path": SSHD_CONFIG, "original": sshd, "updated": _replace_banner(sshd, custom_path)})

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 로그인 경고/SSH Banner 설정 예정 - "
            + summarize([change["path"] for change in changes]),
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    unsafe_paths = [
        change["path"]
        for change in changes
        if not safe_path(change["path"], must_exist=change["original"] is not None)
    ]
    if unsafe_paths:
        return result(
            CODE,
            TITLE,
            FAILED,
            "심볼릭 링크 또는 안전하지 않은 경로: " + summarize(unsafe_paths),
        )
    if any(change["path"] == SSHD_CONFIG for change in changes) and not command_exists("sshd"):
        return result(CODE, TITLE, FAILED, "sshd 설정 검증 명령을 찾지 못해 변경하지 않음")

    backups = []
    created_paths = []
    for change in changes:
        if change["original"] is None:
            created_paths.append(change["path"])
            continue
        backup = backup_file(change["path"])
        if backup is None:
            return result(
                CODE,
                TITLE,
                FAILED,
                f"{change['path']}: 백업 실패로 파일을 변경하지 않음"
                + (f" | 완료된 백업: {summarize(backups)}" if backups else ""),
            )
        backups.append(backup)

    for change in changes:
        if not write_text(change["path"], change["updated"]):
            return _failure(f"{change['path']}: 쓰기 실패", backups, created_paths)
        if change["path"] == ISSUE_NET and (
            not set_file_mode(ISSUE_NET, 0o644)
            or not set_file_owner(ISSUE_NET, "root", "root")
        ):
            return _failure(
                f"{ISSUE_NET}: root:root/0644 설정 실패",
                backups,
                created_paths,
            )

    if any(change["path"] == SSHD_CONFIG for change in changes):
        code, out, err = run_command(["sshd", "-t", "-f", SSHD_CONFIG], timeout=20)
        if code != 0:
            return _failure(
                f"sshd 설정 검증 실패({err or out or code})",
                backups,
                created_paths,
            )

    unit, reload_error = _reload_ssh()
    if reload_error:
        return _failure(reload_error, backups, created_paths, unit)
    if not _custom_warning_path() or (
        read_text(SSHD_CONFIG) is not None and not _ssh_banner_path()
    ):
        return _failure(
            "조치 후 로그인 경고/SSH Banner 재확인 실패",
            backups,
            created_paths,
            unit,
        )

    return result(
        CODE,
        TITLE,
        FIXED,
        "로그인 경고 메시지 및 SSH Banner 설정 완료: "
        + summarize([change["path"] for change in changes])
        + (f" | 백업: {summarize(backups)}" if backups else " | 경고 파일 신규 생성"),
    )

"""U-51 DNS 동적 업데이트 제한 조치."""

import os
import re

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    command_exists,
    read_text,
    result,
    run_command,
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-51"
TITLE = "DNS 서비스의 취약한 동적 업데이트 설정 금지"

NAMED_CONFS = (
    "/etc/bind/named.conf.local",
    "/etc/bind/named.conf",
    "/etc/named.conf",
)

_ALLOW_ANY_RE = re.compile(
    r"allow-update\s*\{\s*any\s*;\s*\}", re.IGNORECASE
)


def _mask_comments(content):
    """BIND 주석을 공백으로 가려 원문의 문자 위치를 보존한다."""
    chars = list(content)
    index = 0
    quote = None
    while index < len(chars):
        if quote:
            if chars[index] == "\\":
                index += 2
                continue
            if chars[index] == quote:
                quote = None
            index += 1
            continue
        if chars[index] in ("'", '"'):
            quote = chars[index]
            index += 1
            continue
        if chars[index] == "#" or content.startswith("//", index):
            end = content.find("\n", index)
            if end < 0:
                end = len(chars)
            for pos in range(index, end):
                chars[pos] = " "
            index = end
            continue
        if content.startswith("/*", index):
            end = content.find("*/", index + 2)
            end = len(chars) if end < 0 else end + 2
            for pos in range(index, end):
                if chars[pos] not in "\r\n":
                    chars[pos] = " "
            index = end
            continue
        index += 1
    return "".join(chars)


def _load_changes():
    changes = []
    for path in NAMED_CONFS:
        content = read_text(path)
        if content is None:
            continue
        # Checker scans raw text, including comments; neutralize matching examples too.
        masked = content
        matches = list(_ALLOW_ANY_RE.finditer(masked))
        if not matches:
            continue
        updated = content
        for match in reversed(matches):
            updated = updated[:match.start()] + "allow-update { none; }" + updated[match.end():]
        changes.append({"path": path, "original": content, "updated": updated})
    return changes


def _restore(changes):
    errors = []
    for change in changes:
        if not write_text(change["path"], change["original"]):
            errors.append(f"{change['path']}: 원본 복구 실패")
    return errors


def _active_bind_unit():
    for unit in ("bind9", "named"):
        if systemctl_is_active(unit):
            return unit
    return None


def _validation_target(changes):
    changed_paths = {change["path"] for change in changes}
    for path in ("/etc/bind/named.conf", "/etc/named.conf"):
        if read_text(path) is not None:
            return path
    return next(iter(changed_paths))


def _validate(path):
    if not command_exists("named-checkconf"):
        return "named-checkconf 명령을 찾지 못함"
    code, out, err = run_command(["named-checkconf", path], timeout=30)
    if code != 0:
        return f"named-checkconf 실패({err or out or code})"
    return None


def _restart(unit):
    if unit is None:
        return None
    code, out, err = run_command(["systemctl", "restart", unit], timeout=30)
    if code != 0:
        return f"{unit} 재시작 실패({err or out or code})"
    return None


def _failure_with_restore(message, changes, unit, backups):
    restore_errors = _restore(changes)
    restart_error = _restart(unit) if not restore_errors else None
    detail = message
    if restore_errors:
        detail += " | " + summarize(restore_errors)
    else:
        detail += " | 원본 복구 완료"
        if restart_error:
            detail += f" | 복구 후 {restart_error}"
    if backups:
        detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FAILED, detail)


def fix(dry_run=False):
    changes = _load_changes()
    if not changes:
        return None

    paths = [change["path"] for change in changes]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: allow-update { any; }를 none으로 변경 예정 - "
            + summarize(paths),
        )
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    backups = []
    for path in paths:
        backup = backup_file(path)
        if backup is None:
            return result(
                CODE,
                TITLE,
                FAILED,
                f"{path}: 백업 실패로 파일을 변경하지 않음"
                + (f" | 완료된 백업: {summarize(backups)}" if backups else ""),
            )
        backups.append(backup)

    written = []
    for change in changes:
        if not write_text(change["path"], change["updated"]):
            return _failure_with_restore(
                f"{change['path']}: 설정 쓰기 실패", written, None, backups
            )
        written.append(change)

    unit = _active_bind_unit()
    validation_error = _validate(_validation_target(changes))
    if validation_error:
        return _failure_with_restore(validation_error, written, None, backups)

    restart_error = _restart(unit)
    if restart_error:
        return _failure_with_restore(restart_error, written, unit, backups)

    remaining = _load_changes()
    if remaining:
        return _failure_with_restore(
            "조치 후에도 취약 설정 존재: "
            + summarize([change["path"] for change in remaining]),
            written,
            unit,
            backups,
        )

    detail = "allow-update { any; }를 none으로 변경: " + summarize(paths)
    if unit:
        detail += f" | 재시작: {unit}"
    detail += f" | 백업: {summarize(backups)}"
    return result(CODE, TITLE, FIXED, detail)

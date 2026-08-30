"""U-64 unattended-upgrades 기반 주기적 보안 패치 정책을 안전하게 설정한다."""

import os
import re
import stat

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
    write_text,
)
from server_policy import PolicyError, policy_for, require_bool


CODE = "U-64"
TITLE = "주기적 보안 패치 및 벤더 권고사항 적용"
AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
SECURITY_POLICY = "/etc/apt/apt.conf.d/52-5g-measure-security"
REQUIRED_SETTINGS = {
    "APT::Periodic::Update-Package-Lists": "1",
    "APT::Periodic::Unattended-Upgrade": "1",
}
SECURITY_POLICY_CONTENT = (
    "// Open5GS 5G Measure Tool U-64\n"
    "Unattended-Upgrade::Origins-Pattern {\n"
    '    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";\n'
    "};\n"
)


def _strip_comments(content):
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.S)
    lines = []
    for line in content.splitlines():
        quote = False
        escaped = False
        cut = len(line)
        index = 0
        while index < len(line):
            char = line[index]
            if escaped:
                escaped = False
            elif char == "\\" and quote:
                escaped = True
            elif char == '"':
                quote = not quote
            elif not quote and char == "#":
                cut = index
                break
            elif not quote and line.startswith("//", index):
                cut = index
                break
            index += 1
        lines.append(line[:cut])
    return "\n".join(lines)


def _settings(content):
    values = {}
    active = _strip_comments(content or "")
    pattern = re.compile(r'^\s*([A-Za-z0-9:_-]+)\s+"([^"\n]*)"\s*;', re.M)
    for match in pattern.finditer(active):
        values[match.group(1)] = match.group(2)
    return values


def _auto_security_enabled(content=None):
    content = read_text(AUTO_UPGRADES) if content is None else content
    if content is None:
        return False
    values = _settings(content)
    return all(values.get(name) == value for name, value in REQUIRED_SETTINGS.items())


def _security_origin_enabled(content=None):
    content = read_text(SECURITY_POLICY) if content is None else content
    active = _strip_comments(content or "")
    return bool(
        re.search(
            r'origin\s*=\s*Ubuntu[^";]*codename\s*=\s*\$\{distro_codename\}-security',
            active,
            re.I,
        )
    )


def _render_periodic_policy(content):
    active_values = _settings(content)
    lines = content.splitlines(keepends=True)
    output = []
    replaced = set()
    pattern = re.compile(r'^\s*([A-Za-z0-9:_-]+)\s+"[^"\n]*"\s*;')
    for line in lines:
        stripped = _strip_comments(line).strip()
        match = pattern.match(stripped)
        name = match.group(1) if match else None
        if name in REQUIRED_SETTINGS:
            if name not in replaced:
                output.append(f'{name} "{REQUIRED_SETTINGS[name]}";\n')
                replaced.add(name)
            continue
        output.append(line)
    for name, value in REQUIRED_SETTINGS.items():
        if name not in replaced and active_values.get(name) != value:
            if output and not output[-1].endswith(("\n", "\r")):
                output[-1] += "\n"
            output.append(f'{name} "{value}";\n')
    return "".join(output)


def _metadata_ok(path):
    try:
        file_stat = os.stat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return (
        stat.S_ISREG(file_stat.st_mode)
        and file_stat.st_uid == 0
        and stat.S_IMODE(file_stat.st_mode) == 0o644
        and safe_path(path, must_exist=True)
    )


def _rollback(backups, created_paths):
    errors = restore_backups(backups)
    for path in reversed(created_paths):
        if os.path.exists(path):
            try:
                if not safe_path(path, must_exist=True):
                    errors.append(f"{path}: 안전하지 않은 생성 경로로 삭제 거부")
                else:
                    os.unlink(path)
            except OSError as exc:
                errors.append(f"{path}: 생성 파일 삭제 실패({exc})")
    return errors


def _validate_apt_config():
    if not command_exists("apt-config"):
        return "apt-config 명령을 찾지 못함"
    code, out, err = run_command(["apt-config", "dump"], timeout=30)
    if code != 0:
        return f"apt-config dump 실패({err or out or code})"
    if not _auto_security_enabled() or not _security_origin_enabled():
        return "APT 보안 업데이트 유효 설정 재검증 실패"
    return None


def fix(dry_run=False):
    try:
        enabled = require_bool(policy_for(CODE), "enable_unattended_security_updates")
    except PolicyError as exc:
        return result(CODE, TITLE, FAILED, f"서버 정책 오류: {exc}")
    if not enabled:
        return result(CODE, TITLE, FAILED, "서버 정책에서 자동 보안 업데이트가 비활성화됨")
    if not command_exists("unattended-upgrade"):
        return result(CODE, TITLE, FAILED, "unattended-upgrades 패키지가 없어 설정을 적용할 수 없음")

    periodic = read_text(AUTO_UPGRADES)
    security = read_text(SECURITY_POLICY)
    already_good = (
        _auto_security_enabled(periodic)
        and _security_origin_enabled(security)
        and _metadata_ok(AUTO_UPGRADES)
        and _metadata_ok(SECURITY_POLICY)
    )
    if already_good:
        validation_error = _validate_apt_config()
        return None if validation_error is None else result(CODE, TITLE, FAILED, validation_error)

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: unattended-upgrades 주기 설정·Ubuntu security origin·root:root/0644 적용 예정",
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    targets = {
        AUTO_UPGRADES: _render_periodic_policy(periodic or ""),
        SECURITY_POLICY: SECURITY_POLICY_CONTENT,
    }
    backups = []
    created_paths = []
    for path, content in targets.items():
        if not safe_path(path):
            rollback_errors = _rollback(backups, created_paths)
            detail = f"{path}: 심볼릭 링크 또는 안전하지 않은 경로"
            if rollback_errors:
                detail += " | 원복 오류: " + ", ".join(rollback_errors)
            return result(CODE, TITLE, FAILED, detail)
        if os.path.exists(path):
            backup = backup_file(path)
            if backup is None:
                rollback_errors = _rollback(backups, created_paths)
                detail = f"{path}: 백업 실패로 변경하지 않음"
                if rollback_errors:
                    detail += " | 원복 오류: " + ", ".join(rollback_errors)
                return result(CODE, TITLE, FAILED, detail)
            backups.append(backup)
        else:
            created_paths.append(path)
        if (
            not write_text(path, content)
            or not set_file_mode(path, 0o644)
            or not set_file_owner(path, "root", "root")
        ):
            rollback_errors = _rollback(backups, created_paths)
            detail = f"{path}: 쓰기·권한·소유자 설정 실패"
            if rollback_errors:
                detail += " | 원복 오류: " + ", ".join(rollback_errors)
            return result(CODE, TITLE, FAILED, detail)

    validation_error = _validate_apt_config()
    if validation_error or not all(_metadata_ok(path) for path in targets):
        rollback_errors = _rollback(backups, created_paths)
        detail = validation_error or "조치 후 파일 소유자·권한 재검증 실패"
        if rollback_errors:
            detail += " | 원복 오류: " + ", ".join(rollback_errors)
        return result(CODE, TITLE, FAILED, detail)

    return result(
        CODE,
        TITLE,
        FIXED,
        "unattended-upgrades 일일 보안 업데이트·Ubuntu security origin·root:root/0644 적용 완료"
        + (f" | 백업 {len(backups)}개" if backups else " | 새 정책 파일 생성"),
    )

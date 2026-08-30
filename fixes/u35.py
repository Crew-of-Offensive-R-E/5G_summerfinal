"""U-35 공유 서비스에 대한 익명 접근 제한 조치."""

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
    summarize,
    systemctl_is_active,
    write_text,
)


CODE = "U-35"
TITLE = "공유 서비스에 대한 익명 접근 제한 설정"

VSFTPD_FILES = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
PROFTPD_FILES = ("/etc/proftpd/proftpd.conf", "/etc/proftpd.conf")
NFS_EXPORTS = "/etc/exports"
SAMBA_FILES = ("/etc/samba/smb.conf", "/usr/lib/smb.conf")

SERVICE_UNITS = {
    "vsftpd": ("vsftpd.service",),
    "proftpd": ("proftpd.service",),
    "nfs": ("nfs-server.service", "nfs-kernel-server.service"),
    "samba": ("smbd.service", "samba.service"),
}

PROCESS_NAMES = {
    "vsftpd": ("vsftpd",),
    "proftpd": ("proftpd",),
    "nfs": ("rpc.nfsd",),
    "samba": ("smbd",),
}


def _unit_in_use(unit):
    if not command_exists("systemctl"):
        return False
    for action in ("is-active", "is-enabled"):
        code, _, _ = run_command(["systemctl", action, unit])
        if code == 0:
            return True
    return False


def _process_running(name):
    if not command_exists("pgrep"):
        return False
    code, _, _ = run_command(["pgrep", "-x", name])
    return code == 0


def _active_services():
    active = set()
    for service, units in SERVICE_UNITS.items():
        if any(_unit_in_use(unit) for unit in units):
            active.add(service)
            continue
        if any(_process_running(name) for name in PROCESS_NAMES[service]):
            active.add(service)
    return active


def _existing_files(paths):
    return [path for path in paths if os.path.isfile(path)]


def _active_lines(path):
    text = read_text(path)
    if text is None:
        return None
    return [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def _check_vsftpd():
    paths = _existing_files(VSFTPD_FILES)
    if not paths:
        return ["vsftpd 활성 상태이나 설정 파일을 찾지 못함"]

    issues = []
    for path in paths:
        lines = _active_lines(path)
        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue
        values = []
        for number, line in lines:
            match = re.match(r"^\s*anonymous_enable\s*=\s*(\S+)", line, re.I)
            if match:
                values.append((number, match.group(1).upper()))
        if not values:
            issues.append(f"{path}: anonymous_enable 설정 없음")
        elif values[-1][1] != "NO":
            issues.append(
                f"{path}:{values[-1][0]}: anonymous_enable={values[-1][1]}"
            )
    return issues


def _check_proftpd():
    paths = _existing_files(PROFTPD_FILES)
    if not paths:
        return ["ProFTP 활성 상태이나 설정 파일을 찾지 못함"]

    issues = []
    for path in paths:
        lines = _active_lines(path)
        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue
        for number, line in lines:
            if re.match(r"^\s*<Anonymous\b", line, re.I):
                issues.append(f"{path}:{number}: Anonymous 블록 활성")
    return issues


def _check_nfs():
    if not os.path.isfile(NFS_EXPORTS):
        return []
    lines = _active_lines(NFS_EXPORTS)
    if lines is None:
        return [f"{NFS_EXPORTS}: 내용 확인 실패"]

    issues = []
    for number, line in lines:
        options = re.findall(
            r"\b(?:anonuid|anongid)\s*=\s*[^,\s\)]+", line, re.I
        )
        if options:
            issues.append(f"{NFS_EXPORTS}:{number}: {','.join(options)}")
    return issues


def _check_samba():
    paths = _existing_files(SAMBA_FILES)
    if not paths:
        return ["Samba 활성 상태이나 설정 파일을 찾지 못함"]

    issues = []
    for path in paths:
        lines = _active_lines(path)
        if lines is None:
            issues.append(f"{path}: 내용 확인 실패")
            continue
        for number, line in lines:
            match = re.match(r"^\s*guest\s+ok\s*=\s*(\S+)", line, re.I)
            if match and match.group(1).lower() in {"yes", "true", "1"}:
                issues.append(f"{path}:{number}: guest ok={match.group(1)}")
            guest_map = re.match(r"^\s*map\s+to\s+guest\s*=\s*(.+)$", line, re.I)
            if guest_map and guest_map.group(1).strip().lower() != "never":
                issues.append(f"{path}:{number}: map to guest={guest_map.group(1).strip()}")
    return issues


def _get_issues():
    active = _active_services()
    issues = []
    if "vsftpd" in active or _existing_files(VSFTPD_FILES):
        issues.extend(_check_vsftpd())
    if "proftpd" in active or _existing_files(PROFTPD_FILES):
        issues.extend(_check_proftpd())
    if "nfs" in active or os.path.isfile(NFS_EXPORTS):
        issues.extend(_check_nfs())
    if "samba" in active or _existing_files(SAMBA_FILES):
        issues.extend(_check_samba())
    return active, issues


def _backup_and_write(path, original, updated, backups):
    if updated == original:
        return None, False

    backup = backup_file(path)
    if backup is None:
        return f"{path}: 백업 실패로 변경하지 않음", False
    backups.append(backup)

    if not write_text(path, updated):
        return f"{path}: 쓰기 실패", False
    return None, True


def _set_vsftpd(path, backups):
    original = read_text(path)
    if original is None:
        return f"{path}: 읽기 실패", False

    active_values = []
    for line in original.splitlines():
        if line.lstrip().startswith(("#", ";")):
            continue
        match = re.match(r"^\s*anonymous_enable\s*=\s*(\S+)", line, re.I)
        if match:
            active_values.append(match.group(1).upper())
    if active_values and active_values[-1] == "NO":
        return None, False

    output = []
    replaced = False
    for line in original.splitlines(keepends=True):
        if (
            not line.lstrip().startswith(("#", ";"))
            and re.match(r"^\s*anonymous_enable\s*=", line, re.I)
        ):
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            output.append(f"anonymous_enable=NO{newline}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        if output and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        output.append("anonymous_enable=NO\n")
    return _backup_and_write(path, original, "".join(output), backups)


def _disable_proftpd_anonymous(path, backups):
    original = read_text(path)
    if original is None:
        return f"{path}: 읽기 실패", False

    inside = False
    changed = False
    output = []
    for line in original.splitlines(keepends=True):
        stripped = line.strip()
        if (
            not line.lstrip().startswith(("#", ";"))
            and re.match(r"^<Anonymous\b", stripped, re.I)
        ):
            inside = True
        if inside and not line.lstrip().startswith(("#", ";")):
            output.append(f"# U-35 disabled: {line}")
            changed = True
        else:
            output.append(line)
        if inside and re.match(r"^</Anonymous>", stripped, re.I):
            inside = False

    if not changed:
        return None, False
    return _backup_and_write(path, original, "".join(output), backups)


def _remove_nfs_anonymous_options(path, backups):
    original = read_text(path)
    if original is None:
        return f"{path}: 읽기 실패", False

    def clean_group(match):
        retained = [
            option.strip()
            for option in match.group(1).split(",")
            if not re.match(r"^(anonuid|anongid)\s*=", option.strip(), re.I)
        ]
        return "(" + ",".join(retained) + ")"

    output = []
    for line in original.splitlines(keepends=True):
        if line.lstrip().startswith("#"):
            output.append(line)
        else:
            output.append(re.sub(r"\(([^)]*)\)", clean_group, line))
    return _backup_and_write(path, original, "".join(output), backups)


def _disable_samba_guest(path, backups):
    original = read_text(path)
    if original is None:
        return f"{path}: 읽기 실패", False

    changed = False
    output = []
    for line in original.splitlines(keepends=True):
        match = None
        if not line.lstrip().startswith(("#", ";")):
            match = re.match(r"^\s*guest\s+ok\s*=\s*(\S+)", line, re.I)
        guest_map = None
        if not line.lstrip().startswith(("#", ";")):
            guest_map = re.match(r"^\s*map\s+to\s+guest\s*=\s*(.+)$", line, re.I)
        if match and match.group(1).lower() in {"yes", "true", "1"}:
            indent = line[: len(line) - len(line.lstrip())]
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            output.append(f"{indent}guest ok = no{newline}")
            changed = True
        elif guest_map and guest_map.group(1).strip().lower() != "never":
            indent = line[: len(line) - len(line.lstrip())]
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            output.append(f"{indent}map to guest = never{newline}")
            changed = True
        else:
            output.append(line)

    if not changed:
        return None, False
    return _backup_and_write(path, original, "".join(output), backups)


def _restart_active_units(service):
    errors = []
    for unit in SERVICE_UNITS[service]:
        if not systemctl_is_active(unit):
            continue
        code, out, err = run_command(["systemctl", "restart", unit], timeout=20)
        if code != 0:
            errors.append(f"{unit}: 재시작 실패({err or out or code})")
    return errors


def fix(dry_run=False):
    active, before = _get_issues()
    if not before:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            f"dry-run: 공유 서비스 익명 접근 차단 예정 — {summarize(before)}",
        )

    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    backups = []
    changed_services = set()

    actions = {
        "vsftpd": (VSFTPD_FILES, _set_vsftpd),
        "proftpd": (PROFTPD_FILES, _disable_proftpd_anonymous),
        "samba": (SAMBA_FILES, _disable_samba_guest),
    }

    for service, (paths, action) in actions.items():
        existing = _existing_files(paths)
        if not existing:
            if service in active:
                errors.append(f"{service}: 활성 상태이나 설정 파일을 찾지 못함")
            continue
        for path in existing:
            error, changed = action(path, backups)
            if error:
                errors.append(error)
            if changed:
                changed_services.add(service)

    if os.path.isfile(NFS_EXPORTS):
        error, changed = _remove_nfs_anonymous_options(NFS_EXPORTS, backups)
        if error:
            errors.append(error)
        if changed:
            changed_services.add("nfs")

    for service in sorted(changed_services):
        errors.extend(_restart_active_units(service))

    if "nfs" in changed_services and command_exists("exportfs"):
        code, out, err = run_command(["exportfs", "-ra"], timeout=20)
        if code != 0:
            errors.append(f"exportfs -ra 실패({err or out or code})")

    if "samba" in changed_services and command_exists("smbcontrol"):
        code, out, err = run_command(
            ["smbcontrol", "all", "reload-config"], timeout=20
        )
        if code != 0:
            errors.append(f"Samba 설정 다시 읽기 실패({err or out or code})")

    _, remaining = _get_issues()
    if errors or remaining:
        restore_errors = restore_backups(backups)
        for service in sorted(changed_services):
            restore_errors.extend(_restart_active_units(service))
        if "nfs" in changed_services and command_exists("exportfs"):
            code, out, err = run_command(["exportfs", "-ra"], timeout=20)
            if code != 0:
                restore_errors.append(f"원복 후 exportfs -ra 실패({err or out or code})")
        if "samba" in changed_services and command_exists("smbcontrol"):
            code, out, err = run_command(["smbcontrol", "all", "reload-config"], timeout=20)
            if code != 0:
                restore_errors.append(f"원복 후 Samba reload 실패({err or out or code})")
        details = []
        if errors:
            details.append(f"오류: {summarize(errors)}")
        if remaining:
            details.append(f"남은 취약 설정: {summarize(remaining)}")
        if restore_errors:
            details.append(f"원복 오류: {summarize(restore_errors)}")
        elif backups:
            details.append("변경 파일/메타데이터 원복 완료")
        if backups:
            details.append(f"백업: {summarize(backups)}")
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(
        CODE,
        TITLE,
        FIXED,
        "익명·게스트 접근 차단 완료"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

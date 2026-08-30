"""U-66 전용 rsyslog 정책 파일과 서비스 상태를 안전하게 설정한다."""

import os
import stat

from fix_common import (
    FAILED,
    FIXED,
    backup_file,
    capture_service_states,
    command_exists,
    read_text,
    result,
    restore_backups,
    restore_service_states,
    run_command,
    safe_path,
    set_file_mode,
    set_file_owner,
    summarize,
    systemctl_is_active,
    systemctl_is_enabled,
    write_text,
)
from server_policy import PolicyError, policy_for, require_bool, require_choice


CODE = "U-66"
TITLE = "정책에 따른 시스템 로깅 설정"
RSYSLOG_CONF = "/etc/rsyslog.conf"
POLICY_PATH = "/etc/rsyslog.d/99-5g-measure-policy.conf"
RSYSLOG_UNIT = "rsyslog.service"
POLICY_LINES = (
    "*.info /var/log/syslog",
    "*.alert /var/log/syslog",
    "*.emerg *",
    "auth,authpriv.* /var/log/auth.log",
)
POLICY_BLOCK = "# Open5GS 5G Measure Tool U-66\n" + "\n".join(POLICY_LINES) + "\n"


def _active_lines(content):
    return {
        line.strip()
        for line in (content or "").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    }


def _policy_ok(content=None):
    content = read_text(POLICY_PATH) if content is None else content
    return content is not None and set(POLICY_LINES).issubset(_active_lines(content))


def _metadata_ok():
    try:
        file_stat = os.stat(POLICY_PATH)
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return (
        stat.S_ISREG(file_stat.st_mode)
        and file_stat.st_uid == 0
        and stat.S_IMODE(file_stat.st_mode) == 0o644
        and safe_path(POLICY_PATH, must_exist=True)
    )


def _validate():
    if not command_exists("rsyslogd"):
        return "rsyslogd 명령을 찾지 못함"
    code, out, err = run_command(["rsyslogd", "-N1", "-f", RSYSLOG_CONF], timeout=30)
    return None if code == 0 else f"rsyslog 설정 검증 실패({err or out or code})"


def _enable_rsyslog():
    if not command_exists("systemctl"):
        return "systemctl 명령을 찾지 못함"
    code, out, err = run_command(
        ["systemctl", "enable", "--now", RSYSLOG_UNIT], timeout=30
    )
    return None if code == 0 else f"rsyslog 활성화 실패({err or out or code})"


def _rollback(backups, created, service_states):
    errors = restore_backups(backups)
    if created and os.path.exists(POLICY_PATH):
        try:
            if not safe_path(POLICY_PATH, must_exist=True):
                errors.append(f"{POLICY_PATH}: 안전하지 않은 생성 경로로 삭제 거부")
            else:
                os.unlink(POLICY_PATH)
        except OSError as exc:
            errors.append(f"{POLICY_PATH}: 생성 파일 삭제 실패({exc})")
    errors.extend(restore_service_states(service_states))
    original_state = service_states.get(RSYSLOG_UNIT, {})
    if original_state.get("active") and command_exists("systemctl"):
        code, out, err = run_command(["systemctl", "restart", RSYSLOG_UNIT], timeout=30)
        if code != 0:
            errors.append(f"rsyslog 원복 설정 재적용 실패({err or out or code})")
    return errors


def fix(dry_run=False):
    try:
        policy = policy_for(CODE)
        backend = require_choice(policy, "logging_backend", {"rsyslog"})
        enable_service = require_bool(policy, "enable_service")
    except PolicyError as exc:
        return result(CODE, TITLE, FAILED, f"서버 정책 오류: {exc}")
    if backend != "rsyslog" or not enable_service:
        return result(CODE, TITLE, FAILED, "서버 정책에서 rsyslog 활성화가 승인되지 않음")

    policy_good = _policy_ok()
    active = systemctl_is_active("rsyslog", RSYSLOG_UNIT)
    enabled = systemctl_is_enabled(RSYSLOG_UNIT)
    metadata_good = _metadata_ok()
    if policy_good and active and enabled and metadata_good:
        validation_error = _validate()
        return None if validation_error is None else result(CODE, TITLE, FAILED, validation_error)

    if dry_run:
        actions = []
        if not policy_good:
            actions.append(f"{POLICY_PATH} 전용 정책 적용")
        if not metadata_good:
            actions.append("root:root/0644 적용")
        if not active or not enabled:
            actions.append("rsyslog enable --now")
        actions.append("rsyslogd -N1 재검증")
        return result(CODE, TITLE, FIXED, "dry-run: " + summarize(actions))
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")
    if not safe_path(POLICY_PATH):
        return result(CODE, TITLE, FAILED, f"{POLICY_PATH}: 심볼릭 링크 또는 안전하지 않은 경로")

    service_states = capture_service_states([RSYSLOG_UNIT])
    original = read_text(POLICY_PATH)
    created = original is None
    backups = []
    if not created:
        backup = backup_file(POLICY_PATH)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"{POLICY_PATH}: 백업 실패로 변경하지 않음")
        backups.append(backup)

    errors = []
    if (
        not write_text(POLICY_PATH, POLICY_BLOCK)
        or not set_file_mode(POLICY_PATH, 0o644)
        or not set_file_owner(POLICY_PATH, "root", "root")
    ):
        errors.append(f"{POLICY_PATH}: 쓰기·권한·소유자 설정 실패")
    if not errors:
        validation_error = _validate()
        if validation_error:
            errors.append(validation_error)
    if not errors:
        enable_error = _enable_rsyslog()
        if enable_error:
            errors.append(enable_error)
    if not errors:
        validation_error = _validate()
        if validation_error:
            errors.append(validation_error)
    if not errors and (
        not _policy_ok()
        or not _metadata_ok()
        or not systemctl_is_active("rsyslog", RSYSLOG_UNIT)
        or not systemctl_is_enabled(RSYSLOG_UNIT)
    ):
        errors.append("조치 후 전용 정책·소유권·권한·active/enabled 상태 재검증 실패")

    if errors:
        rollback_errors = _rollback(backups, created, service_states)
        detail = "오류: " + summarize(errors)
        if rollback_errors:
            detail += " | 원복 오류: " + summarize(rollback_errors)
        else:
            detail += " | 설정·서비스 active/enabled 상태 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    return result(
        CODE,
        TITLE,
        FIXED,
        "rsyslog 전용 정책·root:root/0644·구문검사·서비스 enable/active 적용 완료"
        + (f" | 백업: {summarize(backups)}" if backups else " | 새 정책 파일 생성"),
    )

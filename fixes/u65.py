"""U-65 설치된 NTP 서비스를 사용해 시각 동기화 정책을 안전하게 적용한다."""

import os
import re

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
    write_text,
)
from server_policy import PolicyError, policy_for, require_bool, require_string_list


CODE = "U-65"
TITLE = "NTP 및 시각 동기화 설정"
CHRONY_CONF = "/etc/chrony/chrony.conf"
TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
NTP_CONF = "/etc/ntp.conf"
CONFIGS = (CHRONY_CONF, TIMESYNCD_CONF, NTP_CONF)
BACKENDS = (
    {
        "name": "chrony",
        "config": CHRONY_CONF,
        "unit": "chrony.service",
        "binary": "chronyd",
        "style": "pool",
    },
    {
        "name": "ntp",
        "config": NTP_CONF,
        "unit": "ntp.service",
        "binary": "ntpd",
        "style": "pool",
    },
    {
        "name": "systemd-timesyncd",
        "config": TIMESYNCD_CONF,
        "unit": "systemd-timesyncd.service",
        "binary": None,
        "style": "timesyncd",
    },
)
SERVER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")


def _config_has_ntp(content):
    return bool(re.search(r"(?im)^\s*(server|pool|NTP=)\s*\S+", content or ""))


def _has_ntp_server_config():
    return any(_config_has_ntp(read_text(path)) for path in CONFIGS)


def _process_contains(name):
    if not command_exists("ps"):
        return False
    code, out, _ = run_command(["ps", "ax"], timeout=5)
    return code == 0 and name in out


def _service_running():
    return systemctl_is_active(
        "chrony",
        "chronyd",
        "systemd-timesyncd",
        "ntp",
        "ntpd",
    ) or any(
        _process_contains(name)
        for name in ("chronyd", "ntpd", "systemd-timesyncd")
    )


def _synchronized():
    if not command_exists("timedatectl"):
        return False
    code, out, _ = run_command(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
        timeout=10,
    )
    return code == 0 and out.strip().lower() == "yes"


def _backend_available(backend):
    if systemctl_is_active(backend["name"], backend["unit"]):
        return True
    binary = backend["binary"]
    if binary:
        return command_exists(binary)
    return any(
        os.path.exists(path)
        for path in (
            "/lib/systemd/systemd-timesyncd",
            "/usr/lib/systemd/systemd-timesyncd",
        )
    ) or os.path.exists(TIMESYNCD_CONF)


def _select_backend():
    active = [
        backend
        for backend in BACKENDS
        if systemctl_is_active(backend["name"], backend["unit"])
    ]
    if active:
        return active[0]
    existing = [
        backend
        for backend in BACKENDS
        if os.path.exists(backend["config"]) and _backend_available(backend)
    ]
    if existing:
        return existing[0]
    return next(
        (backend for backend in BACKENDS if _backend_available(backend)),
        None,
    )


def _validated_servers(policy):
    servers = require_string_list(policy, "ntp_servers")
    if not servers:
        raise PolicyError("ntp_servers에 승인된 서버를 하나 이상 지정해야 함")
    invalid = [
        server
        for server in servers
        if not SERVER_PATTERN.fullmatch(server)
    ]
    if invalid:
        raise PolicyError(
            "ntp_servers에 호스트명/IP가 아닌 값이 포함됨: " + summarize(invalid)
        )
    return list(dict.fromkeys(servers))


def _render_config(content, backend, servers):
    content = content or ""
    if _config_has_ntp(content):
        return content
    separator = "" if not content or content.endswith("\n") else "\n"
    if backend["style"] == "timesyncd":
        block = (
            "# Open5GS 5G Measure Tool U-65\n"
            "[Time]\n"
            f"NTP={' '.join(servers)}\n"
        )
    else:
        block = "# Open5GS 5G Measure Tool U-65\n" + "".join(
            f"pool {server} iburst\n" for server in servers
        )
    return content + separator + block


def _validate_config(backend):
    content = read_text(backend["config"])
    if not _config_has_ntp(content):
        return f"{backend['config']}: NTP 서버 설정 재확인 실패"
    if backend["name"] == "chrony" and command_exists("chronyd"):
        code, out, err = run_command(
            ["chronyd", "-p", "-f", backend["config"]],
            timeout=20,
        )
        if code != 0:
            return f"chrony 설정 검증 실패({err or out or code})"
    return None


def _enable_restart(backend):
    if not command_exists("systemctl"):
        return "systemctl 명령을 찾지 못함"
    code, out, err = run_command(
        ["systemctl", "enable", "--now", backend["unit"]],
        timeout=30,
    )
    if code != 0:
        return f"{backend['name']} 활성화 실패({err or out or code})"
    code, out, err = run_command(
        ["systemctl", "restart", backend["unit"]],
        timeout=30,
    )
    if code != 0:
        return f"{backend['name']} 재시작 실패({err or out or code})"
    return None


def _rollback(backups, created, service_states, backend):
    errors = restore_backups(backups)
    if created and os.path.exists(backend["config"]):
        try:
            if not safe_path(backend["config"], must_exist=True):
                errors.append(
                    f"{backend['config']}: 안전하지 않은 생성 경로로 삭제 거부"
                )
            else:
                os.unlink(backend["config"])
        except OSError as exc:
            errors.append(f"{backend['config']}: 생성 파일 삭제 실패({exc})")
    errors.extend(restore_service_states(service_states))
    original = service_states.get(backend["unit"], {})
    if original.get("active") and command_exists("systemctl"):
        code, out, err = run_command(
            ["systemctl", "restart", backend["unit"]],
            timeout=30,
        )
        if code != 0:
            errors.append(
                f"{backend['name']} 원복 설정 재적용 실패({err or out or code})"
            )
    return errors


def fix(dry_run=False):
    try:
        policy = policy_for(CODE)
        servers = _validated_servers(policy)
        enable_service = require_bool(policy, "enable_service")
    except PolicyError as exc:
        return result(CODE, TITLE, FAILED, f"서버 정책 오류: {exc}")
    if not enable_service:
        return result(CODE, TITLE, FAILED, "서버 정책에서 NTP 서비스 활성화가 승인되지 않음")

    backend = _select_backend()
    if backend is None:
        return result(
            CODE,
            TITLE,
            FAILED,
            "설치된 NTP 구현(chrony/ntp/systemd-timesyncd)을 찾지 못해 패키지 설치 없이 조치 불가",
        )

    current = read_text(backend["config"])
    configured_for_backend = _config_has_ntp(current)
    active = systemctl_is_active(backend["name"], backend["unit"])
    if configured_for_backend and active:
        validation_error = _validate_config(backend)
        return None if validation_error is None else result(
            CODE,
            TITLE,
            FAILED,
            validation_error,
        )

    updated = _render_config(current, backend, servers)
    if dry_run:
        actions = []
        if updated != (current or ""):
            actions.append(
                f"{backend['config']}에 NTP={' '.join(servers)} 설정"
            )
        if not active:
            actions.append(f"{backend['unit']} enable --now")
        actions.extend((f"{backend['unit']} restart", "설정·active 상태 재검증"))
        return result(CODE, TITLE, FIXED, "dry-run: " + summarize(actions))

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")
    if not safe_path(backend["config"], must_exist=current is not None):
        return result(
            CODE,
            TITLE,
            FAILED,
            f"{backend['config']}: 심볼릭 링크 또는 안전하지 않은 경로",
        )

    service_states = capture_service_states([backend["unit"]])
    backups = []
    created = current is None
    changed = updated != (current or "")
    if changed and not created:
        backup = backup_file(backend["config"])
        if backup is None:
            return result(
                CODE,
                TITLE,
                FAILED,
                f"{backend['config']}: 백업 실패로 변경하지 않음",
            )
        backups.append(backup)

    errors = []
    if changed and (
        not write_text(backend["config"], updated)
        or not set_file_mode(backend["config"], 0o644)
        or not set_file_owner(backend["config"], "root", "root")
    ):
        errors.append(f"{backend['config']}: 쓰기·root:root/0644 설정 실패")
    if not errors:
        validation_error = _validate_config(backend)
        if validation_error:
            errors.append(validation_error)
    if not errors:
        service_error = _enable_restart(backend)
        if service_error:
            errors.append(service_error)
    if not errors and (
        not _config_has_ntp(read_text(backend["config"]))
        or not _has_ntp_server_config()
        or not systemctl_is_active(backend["name"], backend["unit"])
    ):
        errors.append("조치 후 NTP 서버 설정·서비스 active 상태 재검증 실패")

    if errors:
        rollback_errors = _rollback(
            backups,
            created and changed,
            service_states,
            backend,
        )
        detail = "오류: " + summarize(errors)
        if rollback_errors:
            detail += " | 원복 오류: " + summarize(rollback_errors)
        else:
            detail += " | 설정·서비스 active/enabled 상태 원복 완료"
        return result(CODE, TITLE, FAILED, detail)

    sync_detail = (
        "동기화 완료"
        if _synchronized()
        else "서비스 active 확인(최초 동기화는 네트워크 응답 후 완료)"
    )
    return result(
        CODE,
        TITLE,
        FIXED,
        f"{backend['name']} NTP 서버 설정·활성화·재검증 완료: {sync_detail}"
        + (f" | 백업: {summarize(backups)}" if backups else ""),
    )

"""U-43 NIS/NIS+ 서비스 비활성화 조치."""

import os

from fix_common import (
    FAILED,
    FIXED,
    capture_service_states,
    MANUAL,
    pgrep_any,
    result,
    restore_service_states,
    run_command,
    summarize,
    systemctl_is_active,
)
from server_policy import PolicyError, policy_for, require_bool


CODE = "U-43"
TITLE = "NIS, NIS+ 점검"

NIS_SERVICES = (
    "ypserv",
    "ypbind",
    "ypxfrd",
    "rpc.yppasswdd",
    "rpc.ypupdated",
    "nis",
)

PROCESS_MARKER = "ypserv/ypbind (pgrep)"


def _get_active():
    active = [service for service in NIS_SERVICES if systemctl_is_active(service)]
    if pgrep_any("ypserv", "ypbind"):
        active.append(PROCESS_MARKER)
    return active


def fix(dry_run=False):
    before = _get_active()
    if not before:
        return None

    try:
        required = require_bool(policy_for(CODE), "nis_required")
    except PolicyError as exc:
        return result(CODE, TITLE, MANUAL, f"서버 정책 확인 필요: {exc}")
    if required:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "정책상 NIS 사용 서버이므로 자동 중지하지 않음: " + summarize(before),
        )

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 정책상 불필요한 NIS 서비스 중지·비활성화 예정 — "
            + summarize(before),
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors = []
    changed_services = [service for service in before if service != PROCESS_MARKER]
    service_states = capture_service_states(changed_services)
    for service in before:
        if service == PROCESS_MARKER:
            continue
        code, out, err = run_command(
            ["systemctl", "disable", "--now", service], timeout=30
        )
        if code != 0:
            errors.append(f"{service}: 중지·비활성화 실패({err or out or code})")

    remaining = _get_active()
    if errors or remaining:
        restore_errors = restore_service_states(service_states)
        details = []
        if errors:
            details.append("오류: " + summarize(errors))
        if remaining:
            details.append("남은 활성 서비스: " + summarize(remaining))
        if restore_errors:
            details.append("서비스 상태 원복 오류: " + summarize(restore_errors))
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(
        CODE,
        TITLE,
        FIXED,
        "Open5GS 단일 서버 정책에 따라 NIS/NIS+ 서비스 중지·비활성화 완료",
    )
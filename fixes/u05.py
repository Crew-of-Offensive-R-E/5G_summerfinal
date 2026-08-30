"""U-05 root 이외의 UID 0 금지 조치."""

import os
import tempfile
from pathlib import Path

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    read_text,
    parse_passwd,
    backup_file,
    command_exists,
    run_command,
    summarize,
)


CODE = "U-05"
TITLE = "root 이외의 UID 0 금지"
TARGET = "/etc/passwd"
PROTECTED_ACCOUNTS = {"open5gs", "mongodb"}


def _next_unused_uids(count):
    used = {user["uid"] for user in parse_passwd()}
    selected = []
    candidate = 1000
    while len(selected) < count:
        if candidate not in used and candidate != 65534:
            selected.append(candidate)
            used.add(candidate)
        candidate += 1
    return selected


def _changed_passwd(text, assignments):
    """계정명별 UID를 바꾸되 passwd의 나머지 필드는 그대로 보존한다."""
    uid_by_name = dict(assignments)
    lines = []
    changed = set()
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 7 and fields[0] in uid_by_name:
            fields[2] = str(uid_by_name[fields[0]])
            line = ":".join(fields)
            changed.add(fields[0])
        lines.append(line)
    if changed != set(uid_by_name):
        return None
    return "\n".join(lines) + "\n"


def _install_passwd(text):
    """cppw로 잠금을 획득한 뒤 /etc/passwd를 교체한다."""
    fd, temporary = tempfile.mkstemp(prefix="u05-passwd-", dir="/tmp", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, 0o600)
        code, output, error = run_command(["cppw", temporary], timeout=30)
        return code == 0, error or output
    except OSError as exc:
        return False, str(exc)
    finally:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            pass


def fix(dry_run=False):
    duplicate_root_accounts = [
        user for user in parse_passwd()
        if user["uid"] == 0 and user["name"] != "root"
    ]
    if not duplicate_root_accounts:
        return None

    names = [user["name"] for user in duplicate_root_accounts]
    protected = sorted(set(names) & PROTECTED_ACCOUNTS)
    if protected:
        return result(
            CODE, TITLE, MANUAL,
            "서비스 계정 UID 변경 전 영향 확인 필요: " + summarize(protected),
        )
    if not command_exists("cppw"):
        return result(CODE, TITLE, FAILED, "cppw 명령을 찾을 수 없음")

    original = read_text(TARGET)
    if original is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일 읽기 실패")

    assignments = list(zip(names, _next_unused_uids(len(names))))
    assignment_text = [f"{name}->UID {uid}" for name, uid in assignments]
    if dry_run:
        return result(
            CODE, TITLE, FIXED,
            "dry-run: " + summarize(assignment_text),
        )

    new_text = _changed_passwd(original, assignments)
    if new_text is None:
        return result(CODE, TITLE, FAILED, "UID 변경 대상이 /etc/passwd와 일치하지 않음")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"백업 실패: {TARGET}")

    installed, install_detail = _install_passwd(new_text)
    if not installed:
        return result(CODE, TITLE, FAILED, f"UID 변경 실패: {install_detail}")

    remaining = [
        user["name"] for user in parse_passwd()
        if user["uid"] == 0 and user["name"] != "root"
    ]
    if remaining:
        _install_passwd(original)
        return result(CODE, TITLE, FAILED, "UID 0 중복 검증 실패로 원본 복원")

    return result(
        CODE, TITLE, FIXED,
        "root 외 UID 0 계정을 고유 UID로 변경: "
        + summarize(assignment_text)
        + "; 기존 UID 0 소유 파일은 root 소유로 유지"
        + f"; 백업: {backup}",
    )

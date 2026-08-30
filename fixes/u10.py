"""U-10 동일한 UID 금지 조치."""

import os
import tempfile
from collections import defaultdict
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


CODE = "U-10"
TITLE = "동일한 UID 금지"
TARGET = "/etc/passwd"
PROTECTED_ACCOUNTS = {"root", "open5gs", "mongodb"}


def _duplicate_uids():
    by_uid = defaultdict(list)
    for user in parse_passwd():
        by_uid[user["uid"]].append(user["name"])
    return {
        uid: names for uid, names in by_uid.items()
        if len(names) > 1
    }


def _change_targets(duplicates):
    targets = []
    conflicts = []
    for uid, names in sorted(duplicates.items()):
        protected = [name for name in names if name in PROTECTED_ACCOUNTS]
        if len(protected) > 1:
            conflicts.append(f"UID {uid}: {','.join(protected)}")
            continue
        keeper = protected[0] if protected else names[0]
        targets.extend((name, uid) for name in names if name != keeper)
    return targets, conflicts


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
    uid_by_name = {name: new_uid for name, _, new_uid in assignments}
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
    fd, temporary = tempfile.mkstemp(prefix="u10-passwd-", dir="/tmp", text=True)
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
    duplicates = _duplicate_uids()
    if not duplicates:
        return None

    targets, conflicts = _change_targets(duplicates)
    if conflicts:
        return result(
            CODE, TITLE, MANUAL,
            "보호 대상 서비스 계정 간 UID 충돌 수동 확인 필요: "
            + summarize(conflicts),
        )
    if not command_exists("cppw"):
        return result(CODE, TITLE, FAILED, "cppw 명령을 찾을 수 없음")

    original = read_text(TARGET)
    if original is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 파일 읽기 실패")

    new_uids = _next_unused_uids(len(targets))
    assignments = [
        (name, old_uid, new_uid)
        for (name, old_uid), new_uid in zip(targets, new_uids)
    ]
    detail_items = [
        f"{name}:UID {old_uid}->{new_uid}"
        for name, old_uid, new_uid in assignments
    ]
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: " + summarize(detail_items))

    new_text = _changed_passwd(original, assignments)
    if new_text is None:
        return result(CODE, TITLE, FAILED, "UID 변경 대상이 /etc/passwd와 일치하지 않음")

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"백업 실패: {TARGET}")

    installed, install_detail = _install_passwd(new_text)
    if not installed:
        return result(CODE, TITLE, FAILED, f"UID 변경 실패: {install_detail}")

    if _duplicate_uids():
        _install_passwd(original)
        return result(CODE, TITLE, FAILED, "중복 UID 검증 실패로 원본 복원")

    return result(
        CODE, TITLE, FIXED,
        "중복 계정 UID를 고유 값으로 변경: "
        + summarize(detail_items)
        + "; 기존 UID 소유 파일은 기존 계정 소유로 유지"
        + f"; 백업: {backup}",
    )

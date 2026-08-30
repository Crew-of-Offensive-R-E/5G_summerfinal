"""U-63 sudoers 파일·디렉터리 소유권 및 권한 조치."""

import os
import stat

from fix_common import FAILED, FIXED, MANUAL, backup_file, result, summarize


CODE = "U-63"
TITLE = "sudo 명령어 접근 관리"
SUDOERS = "/etc/sudoers"
SUDOERS_D = "/etc/sudoers.d"
SAFE_FILE_MODES = {0o400, 0o440, 0o600, 0o640}


def _sudoers_d_files():
    if not os.path.isdir(SUDOERS_D):
        return []
    paths = []
    for root, _, files in os.walk(SUDOERS_D):
        paths.extend(os.path.join(root, name) for name in files)
    return paths


def _state(path):
    item = os.lstat(path)
    return {
        "path": path,
        "uid": item.st_uid,
        "gid": item.st_gid,
        "mode": stat.S_IMODE(item.st_mode),
        "is_dir": stat.S_ISDIR(item.st_mode),
        "is_file": stat.S_ISREG(item.st_mode),
        "is_link": stat.S_ISLNK(item.st_mode),
    }


def _plan():
    if not os.path.exists(SUDOERS):
        return None, [f"{SUDOERS}: 파일 없음"]
    paths = [SUDOERS] + _sudoers_d_files()
    if os.path.isdir(SUDOERS_D):
        paths.append(SUDOERS_D)
    states = []
    unsafe = []
    for path in paths:
        try:
            item = _state(path)
        except OSError as exc:
            unsafe.append(f"{path}: 메타데이터 확인 실패({exc})")
            continue
        if item["is_link"] or not (item["is_file"] or item["is_dir"]):
            unsafe.append(f"{path}: 심볼릭 링크 또는 비정규 항목")
            continue
        desired_mode = item["mode"]
        if item["is_dir"]:
            if item["uid"] != 0 or item["gid"] != 0 or item["mode"] & 0o007:
                desired_mode = 0o750
        elif item["uid"] != 0 or item["gid"] != 0 or item["mode"] not in SAFE_FILE_MODES:
            desired_mode = 0o440
        if item["uid"] != 0 or item["gid"] != 0 or desired_mode != item["mode"]:
            item["desired_mode"] = desired_mode
            states.append(item)
    return states, unsafe


def _apply(item):
    try:
        os.chown(item["path"], 0, 0)
        os.chmod(item["path"], item["desired_mode"])
        return None
    except OSError as exc:
        return f"{item['path']}: 소유권/권한 변경 실패({exc})"


def _restore(states):
    errors = []
    for item in states:
        try:
            os.chown(item["path"], item["uid"], item["gid"])
            os.chmod(item["path"], item["mode"])
        except OSError as exc:
            errors.append(f"{item['path']}: 메타데이터 원복 실패({exc})")
    return errors


def fix(dry_run=False):
    changes, unsafe = _plan()
    if changes is None:
        return result(CODE, TITLE, MANUAL, summarize(unsafe))
    if unsafe:
        return result(CODE, TITLE, MANUAL, "안전하게 자동 변경할 수 없는 sudoers 항목: " + summarize(unsafe))
    if not changes:
        return None
    if dry_run:
        return result(
            CODE, TITLE, FIXED,
            "dry-run: sudoers 소유권/권한 교정 예정 - " + summarize([item["path"] for item in changes]),
        )
    if os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    backups = []
    for item in changes:
        if item["is_dir"]:
            continue
        backup = backup_file(item["path"])
        if backup is None:
            return result(
                CODE, TITLE, FAILED,
                f"{item['path']}: 백업 실패로 메타데이터를 변경하지 않음"
                + (f" | 완료된 백업: {summarize(backups)}" if backups else ""),
            )
        backups.append(backup)

    applied = []
    for item in changes:
        error = _apply(item)
        if error:
            restore_errors = _restore(applied)
            detail = error + " | " + ("원래 메타데이터 복구 완료" if not restore_errors else summarize(restore_errors))
            if backups:
                detail += f" | 백업: {summarize(backups)}"
            return result(CODE, TITLE, FAILED, detail)
        applied.append(item)

    remaining, unsafe_after = _plan()
    if remaining or unsafe_after:
        restore_errors = _restore(applied)
        detail = "조치 후 sudoers 소유권/권한 재확인 실패"
        detail += " | " + ("원래 메타데이터 복구 완료" if not restore_errors else summarize(restore_errors))
        if backups:
            detail += f" | 백업: {summarize(backups)}"
        return result(CODE, TITLE, FAILED, detail)
    return result(
        CODE, TITLE, FIXED,
        "sudoers 소유권/권한 교정 완료: " + summarize([item["path"] for item in changes])
        + (f" | 백업: {summarize(backups)}" if backups else " | 디렉터리 메타데이터만 변경"),
    )

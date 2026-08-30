"""U-26 /dev 내 일반 파일을 백업 영역으로 격리하는 조치."""

import os
import shutil
import stat
import time
from pathlib import Path

from fix_common import FIXED, FAILED, result, backup_file, summarize


CODE = "U-26"
TITLE = "/dev에 존재하지 않는 device 파일 점검"
TARGET = "/dev"
QUARANTINE_ROOT = "/var/backups/5g-measure-tool/u26-quarantine"
EXCLUDED = {"/dev/shm", "/dev/mqueue", "/dev/pts", "/dev/hugepages"}


def _regular_files():
    try:
        root_device = os.stat(TARGET).st_dev
    except OSError:
        return None

    found = []
    for current, dirs, files in os.walk(TARGET, topdown=True, followlinks=False):
        kept = []
        for name in dirs:
            path = os.path.join(current, name)
            if path in EXCLUDED or os.path.islink(path):
                continue
            try:
                if os.stat(path).st_dev == root_device:
                    kept.append(name)
            except OSError:
                continue
        dirs[:] = kept

        for name in files:
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if info.st_dev == root_device and stat.S_ISREG(info.st_mode):
                found.append(path)
    return sorted(found)


def _restore(moved):
    for original, quarantined in reversed(moved):
        try:
            os.makedirs(os.path.dirname(original), exist_ok=True)
            shutil.move(quarantined, original)
        except OSError:
            pass


def fix(dry_run=False):
    files = _regular_files()
    if files is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 디렉터리를 확인할 수 없음")
    if not files:
        return None

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: /dev/shm·mqueue 등 예외를 제외한 일반 파일 격리 예정: "
            + summarize(files, limit=10),
        )

    backups = []
    for path in files:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    quarantine = Path(QUARANTINE_ROOT) / str(int(time.time()))
    try:
        quarantine.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        return result(CODE, TITLE, FAILED, f"격리 디렉터리 생성 실패: {exc}")

    moved = []
    for path in files:
        relative = Path(path).relative_to(TARGET)
        destination = quarantine / relative
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(path, destination)
            moved.append((path, str(destination)))
        except OSError as exc:
            _restore(moved)
            return result(CODE, TITLE, FAILED, f"{path} 격리 실패, 복원 시도: {exc}")

    remaining = _regular_files()
    if remaining:
        _restore(moved)
        return result(CODE, TITLE, FAILED, "격리 검증 실패로 원위치 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "일반 파일을 삭제하지 않고 격리: " + summarize(files, limit=10)
        + f"; 격리 위치: {quarantine}"
        + "; 백업: " + summarize(backups, limit=10),
    )

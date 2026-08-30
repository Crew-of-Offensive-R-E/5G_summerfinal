"""U-31 홈 디렉터리 소유자 및 권한 설정 조치."""

import os
import stat
from collections import defaultdict

from fix_common import FIXED, FAILED, MANUAL, NOLOGIN_SHELLS, result, parse_passwd, summarize


CODE = "U-31"
TITLE = "홈 디렉토리 소유자 및 권한"
PROTECTED_SERVICE_ACCOUNTS = {"open5gs", "mongodb"}
NONLOGIN_EXTRA = {"/bin/sync", "/sbin/halt", "/sbin/shutdown"}


def _managed(user):
    """소유자를 해당 계정으로 자동 변경해도 되는 실제 전용 홈만 선별한다."""
    home = user["home"]
    interactive = (
        user["shell"] not in NOLOGIN_SHELLS
        and user["shell"] not in NONLOGIN_EXTRA
    )
    if user["name"] == "root" and home == "/root":
        return True
    if user["name"] in PROTECTED_SERVICE_ACCOUNTS:
        return True
    return user["uid"] >= 1000 and interactive and home.startswith("/home/")


def _inspect():
    by_home = defaultdict(list)
    for user in parse_passwd():
        home = user["home"]
        if home and os.path.isdir(home):
            by_home[home].append(user)

    automatic = []
    manual = []
    for home, users in sorted(by_home.items()):
        try:
            info = os.stat(home)
        except OSError:
            manual.append(f"상태 확인 실패:{home}")
            continue
        mode = stat.S_IMODE(info.st_mode)

        managed_users = [user for user in users if _managed(user)]
        if len(users) > 1 and managed_users:
            manual.append(
                f"공유 홈 {home}:" + ",".join(user["name"] for user in users)
            )
            continue

        if managed_users:
            user = managed_users[0]
            if info.st_uid != user["uid"] or mode & 0o022:
                if os.path.islink(home):
                    manual.append(f"홈 심볼릭 링크:{user['name']}:{home}")
                else:
                    automatic.append(
                        (home, user["name"], user["uid"], info.st_uid, info.st_gid, mode)
                    )
            continue

        # daemon, bin 등의 공용 시스템 경로는 root 소유를 유지한다. 다만 임시
        # 점검 코드에서도 취약으로 보는 잘못된 소유자/other-write는 수동 확인한다.
        expected_uids = {0, *(user["uid"] for user in users)}
        if info.st_uid not in expected_uids or mode & stat.S_IWOTH:
            manual.append(
                f"시스템 계정 홈 {home}(uid={info.st_uid},mode={mode:03o})"
            )

    return automatic, manual


def _restore(changed):
    for home, uid, gid, mode in reversed(changed):
        try:
            os.chown(home, uid, gid)
            os.chmod(home, mode)
        except OSError:
            pass


def fix(dry_run=False):
    automatic, manual = _inspect()
    if manual:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "공용 경로 또는 공유·심볼릭 링크 홈의 소유권 정책 확인 필요: "
            + summarize(manual, limit=10),
        )
    if not automatic:
        return None

    changes = [f"{name}:{home}" for home, name, *_ in automatic]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 해당 계정 소유 및 그룹/기타 사용자 쓰기 제거 예정: "
            + summarize(changes),
        )

    changed = []
    for home, _, target_uid, old_uid, gid, mode in automatic:
        changed.append((home, old_uid, gid, mode))
        try:
            os.chown(home, target_uid, gid)
            os.chmod(home, mode & ~0o022)
        except OSError as exc:
            _restore(changed)
            return result(CODE, TITLE, FAILED, f"{home} 변경 실패, 복원 시도: {exc}")

    remaining, remaining_manual = _inspect()
    if remaining or remaining_manual:
        _restore(changed)
        return result(CODE, TITLE, FAILED, "홈 디렉터리 검증 실패로 메타데이터 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "홈 디렉터리를 해당 계정 소유로 변경하고 g/o 쓰기 제거: "
        + summarize(changes),
    )


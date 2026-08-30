"""U-32 로그인 계정의 누락된 홈 디렉터리 생성 조치."""

import os

from fix_common import FIXED, FAILED, MANUAL, NOLOGIN_SHELLS, result, parse_passwd, summarize


CODE = "U-32"
TITLE = "홈 디렉토리로 지정한 디렉토리의 존재 관리"
NONLOGIN_EXTRA = {"/bin/sync", "/sbin/halt", "/sbin/shutdown"}


def _missing_homes():
    missing = []
    for user in parse_passwd():
        if user["shell"] in NOLOGIN_SHELLS or user["shell"] in NONLOGIN_EXTRA:
            continue
        home = user["home"]
        if home and not os.path.isdir(home):
            missing.append(user)
    return missing


def _safe_to_create(user):
    home = user["home"]
    if not os.path.isabs(home) or ".." in home.split(os.sep):
        return False
    if user["name"] == "root":
        return home == "/root" and os.path.isdir("/")
    if user["uid"] < 1000 or not home.startswith("/home/"):
        return False
    return os.path.isdir(os.path.dirname(home))


def _remove_empty(paths):
    for path in reversed(paths):
        try:
            os.rmdir(path)
        except OSError:
            pass


def fix(dry_run=False):
    missing = _missing_homes()
    if not missing:
        return None

    duplicate_root = [
        user["name"] for user in missing
        if user["uid"] == 0 and user["name"] != "root"
    ]
    if duplicate_root:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "U-05에서 UID 0 중복 계정을 먼저 조치해야 함: "
            + summarize(duplicate_root),
        )

    by_home = {}
    duplicate_homes = set()
    for user in missing:
        home = user["home"]
        if home in by_home:
            duplicate_homes.add(home)
        by_home[home] = user

    unsafe = [
        f"{user['name']}:{user['home']}"
        for user in missing
        if not _safe_to_create(user) or user["home"] in duplicate_homes
    ]
    if unsafe:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "계정 필요 여부와 홈 경로를 확인한 뒤 생성 또는 userdel/usermod 필요: "
            + summarize(unsafe, limit=10),
        )

    targets = [f"{user['name']}:{user['home']}" for user in missing]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 로그인 계정 홈 디렉터리 생성 예정: " + summarize(targets),
        )

    created = []
    for user in missing:
        home = user["home"]
        mode = 0o700 if user["name"] == "root" else 0o750
        try:
            os.mkdir(home, mode)
            created.append(home)
            os.chown(home, user["uid"], user["gid"])
            os.chmod(home, mode)
        except OSError as exc:
            _remove_empty(created)
            return result(CODE, TITLE, FAILED, f"{home} 생성 실패, 생성 디렉터리 복원 시도: {exc}")

    remaining = _missing_homes()
    invalid = []
    for user in missing:
        try:
            info = os.stat(user["home"])
            if info.st_uid != user["uid"] or not os.path.isdir(user["home"]):
                invalid.append(user["home"])
        except OSError:
            invalid.append(user["home"])
    if remaining or invalid:
        _remove_empty(created)
        return result(CODE, TITLE, FAILED, "홈 디렉터리 검증 실패로 생성 디렉터리 제거 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "로그인 계정 홈 디렉터리 생성 및 소유자 설정: " + summarize(targets),
    )

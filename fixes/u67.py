"""U-67 확인팀 기준에 맞춰 로그 파일 소유권·타인 쓰기 권한을 안전하게 교정한다."""

import os
try:
    import pwd
except ImportError:  # Windows 정적 검증 호스트
    pwd = None
import stat
from pathlib import Path

from fix_common import FAILED, FIXED, result, safe_path, summarize


CODE = "U-67"
TITLE = "로그 디렉터리 소유자 및 권한 설정"
LOG_DIR = Path("/var/log")
ALLOWED_OWNERS = {"root", "syslog"}
NON_LOGIN_SHELLS = {"false", "nologin"}
DEFAULT_UID_MIN = 1000


def _requires_change(owner, mode, preserve_service_owner=False):
    owner_issue = owner not in ALLOWED_OWNERS and not preserve_service_owner
    return owner_issue or bool(mode & stat.S_IWOTH)


def _desired_uid(owner, current_uid, preserve_service_owner=False):
    if owner in ALLOWED_OWNERS or preserve_service_owner:
        return current_uid
    return 0


def _normalized_account_name(value):
    return "".join(character for character in value.lower() if character.isalnum())


def _is_service_owned_log(path, item, owner):
    """서비스 전용 로그 디렉터리에서 서비스 계정이 직접 쓰는 파일인지 확인한다."""
    if owner in ALLOWED_OWNERS or pwd is None:
        return False
    try:
        relative = path.relative_to(LOG_DIR)
        if len(relative.parts) < 2:
            return False

        account = pwd.getpwnam(owner)
        if account.pw_uid != item.st_uid or account.pw_uid == 0:
            return False

        service_dir = LOG_DIR / relative.parts[0]
        directory = os.lstat(service_dir)
        if stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode):
            return False

        shell_name = os.path.basename(account.pw_shell or "").lower()
        is_service_account = (
            account.pw_uid < DEFAULT_UID_MIN or shell_name in NON_LOGIN_SHELLS
        )
        if not is_service_account:
            return False

        directory_matches_account = (
            directory.st_uid == account.pw_uid or directory.st_gid == account.pw_gid
        )
        directory_name = _normalized_account_name(relative.parts[0])
        account_name = _normalized_account_name(owner)
        name_matches_account = bool(
            directory_name
            and account_name
            and (
                directory_name == account_name
                or directory_name.startswith(account_name)
                or account_name.startswith(directory_name)
            )
        )
        return directory_matches_account or name_matches_account
    except (KeyError, ValueError, PermissionError, OSError):
        return False


def _scan():
    if pwd is None:
        return [], ["pwd 모듈을 사용할 수 없는 호스트"]
    if not LOG_DIR.exists():
        return [], []

    issues = []
    errors = []
    try:
        walker = os.walk(LOG_DIR, followlinks=False)
        for root_dir, _, files in walker:
            for name in files:
                path = Path(root_dir) / name
                try:
                    item = os.lstat(path)
                    if stat.S_ISLNK(item.st_mode):
                        followed = os.stat(path)
                        if not stat.S_ISREG(followed.st_mode):
                            continue
                        owner = pwd.getpwuid(followed.st_uid).pw_name
                        mode = stat.S_IMODE(followed.st_mode)
                        preserve_owner = _is_service_owned_log(path, followed, owner)
                        if _requires_change(owner, mode, preserve_owner):
                            errors.append(
                                f"{path}: 취약한 심볼릭 링크 대상은 자동 변경 거부"
                            )
                        continue
                    if not stat.S_ISREG(item.st_mode):
                        continue
                    owner = pwd.getpwuid(item.st_uid).pw_name
                    mode = stat.S_IMODE(item.st_mode)
                except KeyError:
                    # 확인팀도 UID를 계정명으로 해석하지 못한 파일은 건너뛴다.
                    continue
                except (PermissionError, OSError) as exc:
                    errors.append(f"{path}: 메타데이터 확인 실패({exc})")
                    continue

                preserve_owner = _is_service_owned_log(path, item, owner)
                if not _requires_change(owner, mode, preserve_owner):
                    continue
                issues.append(
                    {
                        "path": str(path),
                        "owner": owner,
                        "uid": item.st_uid,
                        "gid": item.st_gid,
                        "mode": mode,
                        "dev": item.st_dev,
                        "ino": item.st_ino,
                        "desired_uid": _desired_uid(
                            owner, item.st_uid, preserve_owner
                        ),
                        "desired_mode": mode & ~stat.S_IWOTH,
                    }
                )
    except (PermissionError, OSError) as exc:
        errors.append(f"{LOG_DIR}: 탐색 실패({exc})")
    return issues, errors


def _describe(item):
    return (
        f"{item['path']}(owner={item['owner']},mode={item['mode']:03o}"
        f"->uid={item['desired_uid']},mode={item['desired_mode']:03o})"
    )


def _set_metadata(item, restore=False):
    path = item["path"]
    if not safe_path(path, allowed_roots=[str(LOG_DIR)], must_exist=True):
        return f"{path}: 심볼릭 링크 또는 허용 범위 밖 경로"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
        try:
            current = os.fstat(fd)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != item["dev"]
                or current.st_ino != item["ino"]
            ):
                return f"{path}: 검사 후 파일이 교체되어 변경 거부"
            uid = item["uid"] if restore else item["desired_uid"]
            mode = item["mode"] if restore else item["desired_mode"]
            os.fchown(fd, uid, item["gid"])
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        return None
    except (PermissionError, OSError) as exc:
        action = "원복" if restore else "조치"
        return f"{path}: 메타데이터 {action} 실패({exc})"


def _rollback(applied):
    errors = []
    for item in reversed(applied):
        error = _set_metadata(item, restore=True)
        if error:
            errors.append(error)
    return errors


def fix(dry_run=False):
    issues, scan_errors = _scan()
    if scan_errors:
        return result(
            CODE,
            TITLE,
            FAILED,
            "로그 파일을 안전하게 전수 확인하지 못함: " + summarize(scan_errors),
        )
    if not issues:
        return None
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 확인팀 기준 위반 로그 메타데이터 교정 예정 - "
            + summarize([_describe(item) for item in issues]),
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    applied = []
    for item in issues:
        error = _set_metadata(item)
        if error:
            rollback_errors = _rollback(applied)
            detail = error + " | " + (
                "적용된 메타데이터 원복 완료"
                if not rollback_errors
                else "원복 오류: " + summarize(rollback_errors)
            )
            return result(CODE, TITLE, FAILED, detail)
        applied.append(item)

    remaining, errors_after = _scan()
    if remaining or errors_after:
        rollback_errors = _rollback(applied)
        details = []
        if remaining:
            details.append(
                "남은 취약 로그: "
                + summarize([_describe(item) for item in remaining])
            )
        if errors_after:
            details.append("재검증 오류: " + summarize(errors_after))
        details.append(
            "메타데이터 원복 완료"
            if not rollback_errors
            else "원복 오류: " + summarize(rollback_errors)
        )
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(
        CODE,
        TITLE,
        FIXED,
        f"로그 파일 {len(applied)}개의 비허용 소유자·타인 쓰기 권한 교정 및 재검증 완료"
        " | 내용 변경 없이 원래 UID/GID/권한 메타데이터를 롤백 스냅샷으로 보관",
    )

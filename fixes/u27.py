"""U-27 $HOME/.rhosts, /etc/hosts.equiv 보안 설정 조치."""

import os
import stat

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    result,
    parse_passwd,
    read_text,
    backup_file,
    write_text,
    summarize,
)


CODE = "U-27"
TITLE = "$HOME/.rhosts, hosts.equiv 사용 금지"


def _has_plus(text):
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if not active:
            continue
        if any(token.startswith("+") for token in active.split()):
            return True
    return False


def _secure_text(text):
    lines = []
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if active and any(token.startswith("+") for token in active.split()):
            continue
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


def _targets():
    targets = [("/etc/hosts.equiv", 0)]
    seen = {"/etc/hosts.equiv"}
    for user in parse_passwd():
        home = user["home"]
        if not home or not os.path.isdir(home):
            continue
        path = os.path.join(home, ".rhosts")
        if path not in seen:
            targets.append((path, user["uid"]))
            seen.add(path)
    return [(path, uid) for path, uid in targets if os.path.lexists(path)]


def _issues():
    bad = []
    symlinks = []
    for path, expected_uid in _targets():
        if os.path.islink(path):
            symlinks.append(path)
            continue
        try:
            info = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(info.st_mode)
        text = read_text(path)
        if text is None:
            bad.append((path, expected_uid, info.st_uid, info.st_gid, mode, ""))
            continue
        if info.st_uid not in (0, expected_uid) or mode > 0o600 or _has_plus(text):
            target_uid = info.st_uid if info.st_uid in (0, expected_uid) else expected_uid
            bad.append((path, target_uid, info.st_uid, info.st_gid, mode, text))
    return bad, symlinks


def _restore(changed):
    for path, uid, gid, mode, text in reversed(changed):
        write_text(path, text)
        try:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        except OSError:
            pass


def fix(dry_run=False):
    bad, symlinks = _issues()
    if symlinks:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "신뢰 파일 심볼릭 링크의 실제 대상을 확인해야 함: " + summarize(symlinks),
        )
    if not bad:
        return None

    unreadable = [path for path, _, _, _, _, text in bad if read_text(path) is None]
    if unreadable:
        return result(CODE, TITLE, FAILED, "파일 읽기 실패: " + summarize(unreadable))

    paths = [item[0] for item in bad]
    changes = [
        f"{path}(uid={old_uid},mode={mode:04o})->uid={target_uid},mode=0600"
        for path, target_uid, old_uid, _, mode, _ in bad
    ]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: '+' 신뢰 규칙 제거, root/해당 사용자 소유, 0600 적용 예정: "
            + summarize(changes),
        )

    backups = []
    for path in paths:
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        backups.append(backup)

    changed = []
    for path, target_uid, old_uid, gid, mode, text in bad:
        changed.append((path, old_uid, gid, mode, text))
        try:
            if not write_text(path, _secure_text(text)):
                raise OSError("파일 쓰기 실패")
            os.chown(path, target_uid, gid)
            os.chmod(path, 0o600)
        except OSError as exc:
            _restore(changed)
            return result(CODE, TITLE, FAILED, f"{path} 변경 실패, 복원 시도: {exc}")

    remaining, remaining_links = _issues()
    if remaining or remaining_links:
        _restore(changed)
        return result(CODE, TITLE, FAILED, "변경 검증 실패로 원본 복원 시도")

    return result(
        CODE,
        TITLE,
        FIXED,
        "'+' 신뢰 규칙 제거 및 소유자/0600 적용: "
        + summarize(changes)
        + "; 백업: "
        + summarize(backups),
    )

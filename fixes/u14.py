"""U-14 root PATH에서 현재 디렉터리와 빈 경로 제거 조치."""

import os
import re

from fix_common import FIXED, FAILED, MANUAL, result, read_text, backup_file, write_text, summarize


CODE = "U-14"
TITLE = "root 홈, 패스 디렉터리 권한 및 패스 설정"
TARGETS = ("/root/.profile", "/root/.bashrc", "/etc/profile")


def _bad_path(value):
    parts = value.split(":")
    return "" in parts or "." in parts


def _sanitize_path_line(line):
    if line.lstrip().startswith("#") or "PATH" not in line:
        return line
    match = re.search(
        r"(?P<prefix>\bPATH\s*=\s*)(?P<quote>[\"']?)(?P<value>[^\"'\s;]*)(?P=quote)",
        line,
    )
    if not match or not _bad_path(match.group("value")):
        return line

    clean_parts = [part for part in match.group("value").split(":") if part not in {"", "."}]
    replacement = match.group("prefix") + match.group("quote")
    replacement += ":".join(clean_parts) + match.group("quote")
    return line[:match.start()] + replacement + line[match.end():]


def _secure_text(text):
    return "\n".join(_sanitize_path_line(line) for line in text.splitlines()) + "\n"


def _bad_files():
    bad = []
    for path in TARGETS:
        text = read_text(path)
        if text is None:
            continue
        if _secure_text(text) != (text if text.endswith("\n") else text + "\n"):
            bad.append(path)
    return bad


def fix(dry_run=False):
    bad_files = _bad_files()
    current_bad = _bad_path(os.environ.get("PATH", ""))
    if not bad_files and not current_bad:
        return None
    if not bad_files and current_bad:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "현재 실행 환경 PATH에 '.' 또는 빈 경로가 있으나 대상 설정 파일에서는 "
            "원인을 찾지 못함; 호출 스크립트/서비스 환경 확인 필요",
        )

    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: PATH에서 '.' 및 빈 경로 제거 예정: " + summarize(bad_files),
        )

    originals = {}
    backups = []
    for path in bad_files:
        text = read_text(path)
        if text is None:
            return result(CODE, TITLE, FAILED, f"파일 읽기 실패: {path}")
        backup = backup_file(path)
        if backup is None:
            return result(CODE, TITLE, FAILED, f"백업 실패: {path}")
        originals[path] = text
        backups.append(backup)

    written = []
    for path, text in originals.items():
        if not write_text(path, _secure_text(text)):
            for restore_path in written:
                write_text(restore_path, originals[restore_path])
            return result(CODE, TITLE, FAILED, f"쓰기 실패로 변경 파일 복원: {path}")
        written.append(path)

    if _bad_files():
        for path, text in originals.items():
            write_text(path, text)
        return result(CODE, TITLE, FAILED, "PATH 검증 실패로 원본 복원")

    return result(
        CODE,
        TITLE,
        FIXED,
        "PATH에서 '.' 및 빈 경로 제거: " + summarize(bad_files)
        + "; 새 로그인부터 적용; 백업: " + summarize(backups),
    )


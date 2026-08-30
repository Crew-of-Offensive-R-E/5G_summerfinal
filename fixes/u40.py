"""U-40 웹서비스 파일 업로드 및 다운로드 제한 조치.

확인팀 기준에 맞춰 NFS 전체 호스트(*) 허용과 웹 업로드 디렉터리의
실행 가능 파일을 점검한다. 실행 권한은 자동 제거할 수 있지만 NFS 허용
호스트는 서버 정책이 NFS 미사용으로 확정된 경우 해당 export를 주석 처리한다.
"""

import os
import posixpath
import re
import stat

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    command_exists,
    read_text,
    result,
    restore_backups,
    run_command,
    safe_path,
    set_file_mode,
    summarize,
    write_text,
)
from server_policy import (
    PolicyError,
    policy_for,
    require_bool,
    require_string_list,
)


CODE = "U-40"
TITLE = "웹서비스 파일 업로드 및 다운로드 제한"

EXPORTS_PATH = "/etc/exports"
WEB_UPLOAD_DIRS = ("/var/www/html/upload", "/var/www/uploads")
EXECUTE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _nfs_wildcard_issues():
    if not os.path.isfile(EXPORTS_PATH):
        return [], []

    content = read_text(EXPORTS_PATH)
    if content is None:
        return [], [f"{EXPORTS_PATH}: 내용 확인 실패"]

    issues = []
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\*\([^)]*\)", stripped) or re.search(r"\s+\*$", stripped):
            issues.append(f"{EXPORTS_PATH}:{number}: NFS 전체 호스트(*) 허용 - {stripped}")
    return issues, []


def _upload_execute_issues(upload_dirs):
    issues = []
    errors = []

    for upload_dir in upload_dirs:
        if not os.path.isdir(upload_dir):
            continue
        try:
            walker = os.walk(upload_dir, followlinks=False)
            for root_dir, _, filenames in walker:
                for filename in filenames:
                    path = os.path.join(root_dir, filename)
                    try:
                        if os.path.islink(path):
                            target_mode = stat.S_IMODE(os.stat(path).st_mode)
                            if target_mode & EXECUTE_BITS:
                                issues.append({
                                    "path": path,
                                    "mode": target_mode,
                                    "manual": True,
                                    "detail": f"{path}: 실행 가능한 심볼릭 링크 대상(mode={target_mode:03o})",
                                })
                            continue

                        file_stat = os.stat(path)
                        if not stat.S_ISREG(file_stat.st_mode):
                            continue
                        mode = stat.S_IMODE(file_stat.st_mode)
                        if mode & EXECUTE_BITS:
                            issues.append({
                                "path": path,
                                "mode": mode,
                                "manual": False,
                                "detail": f"{path}: 업로드 파일 실행 권한 존재(mode={mode:03o})",
                            })
                    except (FileNotFoundError, PermissionError, OSError) as exc:
                        errors.append(f"{path}: 상태 확인 실패({exc})")
        except (PermissionError, OSError) as exc:
            errors.append(f"{upload_dir}: 탐색 실패({exc})")

    return issues, errors


def _disable_nfs_wildcards(backups):
    original = read_text(EXPORTS_PATH)
    if original is None:
        return f"{EXPORTS_PATH}: 읽기 실패"
    output = []
    changed = False
    for line in original.splitlines(keepends=True):
        stripped = line.strip()
        vulnerable = (
            stripped
            and not stripped.startswith("#")
            and (re.search(r"\*\([^)]*\)", stripped) or re.search(r"\s+\*$", stripped))
        )
        if vulnerable:
            output.append(f"# U-40 disabled by server policy: {line}")
            changed = True
        else:
            output.append(line)
    if not changed:
        return None
    backup = backup_file(EXPORTS_PATH)
    if backup is None:
        return f"{EXPORTS_PATH}: 백업 실패로 변경하지 않음"
    backups.append(backup)
    if not write_text(EXPORTS_PATH, "".join(output)):
        return f"{EXPORTS_PATH}: 쓰기 실패"
    return None


def _scan(upload_dirs):
    wildcard_issues, nfs_errors = _nfs_wildcard_issues()
    execute_issues, upload_errors = _upload_execute_issues(upload_dirs)
    return wildcard_issues, execute_issues, nfs_errors + upload_errors


def fix(dry_run=False):
    try:
        policy = policy_for(CODE)
        nfs_required = require_bool(policy, "nfs_required")
        upload_dirs = require_string_list(policy, "web_upload_dirs")
        follow_symlinks = require_bool(policy, "follow_upload_symlinks")
    except PolicyError as exc:
        return result(CODE, TITLE, MANUAL, f"서버 정책 확인 필요: {exc}")
    if follow_symlinks:
        return result(CODE, TITLE, MANUAL, "업로드 심볼릭 링크 추적 정책은 안전상 자동 조치하지 않음")
    if any(not posixpath.isabs(path) for path in upload_dirs):
        return result(CODE, TITLE, FAILED, "web_upload_dirs는 절대경로로 지정해야 함")
    unsafe_dirs = [
        path for path in upload_dirs
        if not safe_path(path, allowed_roots=WEB_UPLOAD_DIRS)
    ]
    if unsafe_dirs:
        return result(
            CODE,
            TITLE,
            FAILED,
            "허용된 웹 업로드 루트 밖이거나 심볼릭 링크인 경로: " + summarize(unsafe_dirs),
        )

    wildcard_issues, execute_issues, scan_errors = _scan(upload_dirs)
    if scan_errors:
        return result(CODE, TITLE, FAILED, "점검 대상 확인 실패로 변경하지 않음: " + summarize(scan_errors))
    if not wildcard_issues and not execute_issues:
        return None

    manual_execute = [item["detail"] for item in execute_issues if item["manual"]]
    if (wildcard_issues and nfs_required) or manual_execute:
        reasons = ([] if not nfs_required else list(wildcard_issues)) + manual_execute
        return result(CODE, TITLE, MANUAL, "NFS 사용 정책 또는 심볼릭 링크 대상 확인 필요: " + summarize(reasons))

    before = list(wildcard_issues) + [item["detail"] for item in execute_issues]
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: NFS wildcard export 주석 처리 및 업로드 실행 권한 제거 예정 — " + summarize(before))
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 - sudo로 실행하세요")

    errors, backups = [], []
    if wildcard_issues:
        error = _disable_nfs_wildcards(backups)
        if error:
            errors.append(error)

    for item in execute_issues:
        path = item["path"]
        if not safe_path(path, allowed_roots=upload_dirs, must_exist=True):
            errors.append(f"{path}: 허용 업로드 경로 밖이거나 심볼릭 링크이므로 변경 거부")
            continue
        backup = backup_file(path)
        if backup is None:
            errors.append(f"{path}: 백업 실패로 변경하지 않음")
            continue
        backups.append(backup)
        target_mode = item["mode"] & ~EXECUTE_BITS
        if not set_file_mode(path, target_mode):
            errors.append(f"{path}: 실행 권한 제거 실패({item['mode']:03o}->{target_mode:03o})")

    if wildcard_issues and not errors:
        if not command_exists("exportfs"):
            errors.append("exportfs 명령을 찾지 못해 변경된 NFS export를 반영할 수 없음")
        else:
            code, out, err = run_command(["exportfs", "-ra"], timeout=30)
            if code != 0:
                errors.append(f"exportfs -ra 실패({err or out or code})")

    remaining_wildcards, remaining_execute, verify_errors = _scan(upload_dirs)
    if errors or verify_errors or remaining_wildcards or remaining_execute:
        restore_errors = restore_backups(backups)
        details = []
        if errors:
            details.append("오류: " + summarize(errors))
        if verify_errors:
            details.append("재검증 오류: " + summarize(verify_errors))
        if remaining_wildcards:
            details.append("남은 NFS 전체 허용: " + summarize(remaining_wildcards))
        if remaining_execute:
            details.append("남은 실행 가능 파일: " + summarize([item["detail"] for item in remaining_execute]))
        if restore_errors:
            details.append("원복 오류: " + summarize(restore_errors))
        elif backups:
            details.append("변경 파일/메타데이터 원복 완료")
        if backups:
            details.append("백업: " + summarize(backups))
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(CODE, TITLE, FIXED, "NFS wildcard export 차단 및 웹 업로드 파일 실행 권한 제거 완료" + (f" | 백업: {summarize(backups)}" if backups else ""))
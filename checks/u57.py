"""U-57 Ftpusers 파일 설정"""
import os

from check_common import (
    GOOD,
    VULN,
    result,
    read_lines,
    ftp_service_active,
    summarize,
)

CODE = "U-57"
TITLE = "Ftpusers 파일 설정"


def check():
    # 1. FTP 서비스 활성화 여부 확인
    if not ftp_service_active():
        return result(CODE, TITLE, GOOD, "FTP 서비스 활성 징후가 없어 root FTP 직접 접속 위험이 낮습니다.")

    paths = [
        "/etc/ftpusers",
        "/etc/ftpd/ftpusers",
        "/etc/vsftpd/ftpusers",
        "/etc/vsftpd.user_list",
        "/etc/vsftpd/user_list",
    ]
    root_blocked = []

    # 2. ftpusers 설정 파일 내 root 계정 차단 여부 점검 (읽기 전용)
    for path in paths:
        if not os.path.exists(path):
            continue
        entries = [
            line.strip()
            for line in read_lines(path)
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if "root" in entries:
            root_blocked.append(path)

    # 3. 점검 결과 반환
    if root_blocked:
        return result(CODE, TITLE, GOOD, f"root 계정 FTP 접근 차단 설정 확인: {summarize(root_blocked)}")

    return result(CODE, TITLE, VULN, "FTP 서비스가 활성화되어 있으나 ftpusers 파일에 root 계정 차단 설정이 존재하지 않습니다.")

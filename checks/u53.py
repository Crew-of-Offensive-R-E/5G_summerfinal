"""U-53 FTP 서비스 정보 노출 제한"""
import re

from check_common import (
    GOOD,
    VULN,
    result,
    read_lines,
    ftp_service_active,
    summarize,
)

CODE = "U-53"
TITLE = "FTP 서비스 정보 노출 제한"


def check():
    # 1. FTP 서비스 활성화 여부 확인
    if not ftp_service_active():
        return result(CODE, TITLE, GOOD, "FTP 서비스 활성 징후가 없어 배너 정보 노출 위험이 낮습니다.")

    safe_evidence = []
    weak_evidence = []

    # 2. vsftpd 배너 설정 점검 (/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf)
    for path in ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"]:
        for line in read_lines(path):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "ftpd_banner" not in stripped:
                continue
            value = stripped.split("=", 1)[-1].strip().strip("'\"")
            if value and not re.search(r"(vsftp|proftp|ftp\s*server|version|[0-9]+\.[0-9]+)", value, re.I):
                safe_evidence.append(f"{path}:ftpd_banner")
            else:
                weak_evidence.append(f"{path}:ftpd_banner={value or 'empty'}")

    # 3. proftpd 배너 설정 점검 (/etc/proftpd/proftpd.conf, /etc/proftpd.conf)
    for path in ["/etc/proftpd/proftpd.conf", "/etc/proftpd.conf"]:
        for line in read_lines(path):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or not stripped.lower().startswith("serverident"):
                continue
            if re.search(r"\boff\b", stripped, re.I):
                safe_evidence.append(f"{path}:ServerIdent Off")
            elif not re.search(r"(proftp|ftp\s*server|version|[0-9]+\.[0-9]+)", stripped, re.I):
                safe_evidence.append(f"{path}:custom ServerIdent")
            else:
                weak_evidence.append(f"{path}:{stripped}")

    # 4. 점검 결과 판정 (취약점 유무에 따라 GOOD / VULN 반환)
    if not weak_evidence and safe_evidence:
        return result(CODE, TITLE, GOOD, f"FTP 배너 사용자 정의/비노출 설정 확인: {summarize(safe_evidence)}")

    if weak_evidence:
        return result(CODE, TITLE, VULN, f"FTP 배너에 버전 및 서버 정보 노출 위험 존재: {summarize(weak_evidence)}")

    return result(CODE, TITLE, VULN, "FTP 서비스가 활성화되어 있으나 배너 제한(ftpd_banner / ServerIdent) 설정이 명시되지 않았습니다.")

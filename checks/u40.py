import os, re
from check_common import GOOD, VULN, NA, result

CODE = "U-40"
TITLE = "웹서비스 파일 업로드 및 다운로드 제한"

def check():
    vuln_details = []

    # 1. NFS exports 점검
    exports_path = "/etc/exports"
    if os.path.exists(exports_path):
        try:
            with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    # 전체 호스트 허용(*) 및 줄 끝 단독 * 매칭
                    if re.search(r'\*\([^\)]*\)', line) or re.search(r'\s+\*$', line):
                        vuln_details.append(f"NFS 전체 허용: {line}")
        except Exception as e:
            vuln_details.append(f"NFS exports 점검 오류: {str(e)}")

    # 2. 웹 업로드 디렉터리 실행 권한 점검 복원
    web_upload_dirs = ["/var/www/html/upload", "/var/www/uploads"]
    for u_dir in web_upload_dirs:
        if os.path.exists(u_dir):
            try:
                for root_dir, _, files in os.walk(u_dir):
                    for file in files:
                        file_path = os.path.join(root_dir, file)
                        # 실행 권한(0o111) 존재 여부 검사
                        if os.stat(file_path).st_mode & 0o111:
                            vuln_details.append(f"업로드 디렉터리 내 실행 권한 파일 존재: {file_path}")
                            if len(vuln_details) >= 5:
                                break
            except Exception as e:
                vuln_details.append(f"업로드 디렉터리 권한 점검 오류: {str(e)}")

    if vuln_details:
        return result(CODE, TITLE, VULN, f"파일 업로드/다운로드 및 접근 통제 미흡: {', '.join(vuln_details)}")
    
    return result(CODE, TITLE, GOOD, "NFS 접근 통제 및 웹 업로드 디렉터리 실행 권한 설정이 적절합니다.")

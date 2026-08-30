import os
from check_common import GOOD, VULN, NA, result

CODE = "U-35"
TITLE = "공유 서비스에 대한 익명 접근 제한 설정"

def check():
    vuln_reasons = []
    service_found = False

    # 1. vsftpd 점검
    conf_path = "/etc/vsftpd.conf"
    if os.path.exists(conf_path):
        service_found = True
        anonymous_enable = "NO"  # vsftpd 3.x+ 기본값 NO
        try:
            with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "anonymous_enable" in line:
                        parts = line.split("=")
                        if len(parts) == 2:
                            anonymous_enable = parts[1].strip().upper()
            if anonymous_enable == "YES":
                vuln_reasons.append("vsftpd 익명 접근 허용(anonymous_enable=YES)")
        except Exception as e:
            vuln_reasons.append(f"vsftpd 설정 읽기 오류: {str(e)}")

    # 2. ProFTPD 점검
    proftpd_path = "/etc/proftpd/proftpd.conf"
    if os.path.exists(proftpd_path):
        service_found = True
        try:
            with open(proftpd_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "<Anonymous" in content and "UserAlias anonymous" in content:
                    vuln_reasons.append("ProFTPD 익명 접근 설정 존재")
        except Exception as e:
            vuln_reasons.append(f"ProFTPD 설정 읽기 오류: {str(e)}")

    # 3. NFS 점검
    exports_path = "/etc/exports"
    if os.path.exists(exports_path):
        service_found = True
        try:
            with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "anonuid" in content or "anongid" in content:
                    vuln_reasons.append("NFS exports에 익명 접근 관련 옵션(anonuid/anongid) 설정됨")
        except Exception as e:
            vuln_reasons.append(f"NFS exports 설정 읽기 오류: {str(e)}")

    # 4. Samba 점검
    samba_path = "/etc/samba/smb.conf"
    if os.path.exists(samba_path):
        service_found = True
        try:
            with open(samba_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line.startswith("#") or line.startswith(";"):
                        continue
                    if "guest ok = yes" in line or "map to guest = bad user" in line:
                        vuln_reasons.append("Samba 게스트(익명) 접근 허용 설정 존재")
                        break
        except Exception as e:
            vuln_reasons.append(f"Samba 설정 읽기 오류: {str(e)}")

    if not service_found:
        return result(CODE, TITLE, GOOD, "점검 대상 공유 서비스(vsftpd, ProFTPD, Samba 등)가 설치되어 있지 않습니다.")

    if vuln_reasons:
        return result(CODE, TITLE, VULN, f"공유 서비스 익명 접근 허용 미흡: {', '.join(vuln_reasons)}")
    
    return result(CODE, TITLE, GOOD, "모든 공유 서비스에 대한 익명 접근이 적절히 제한되어 있습니다.")

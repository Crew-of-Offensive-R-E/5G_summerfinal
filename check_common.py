"""
common.py — 확인팀 공통 유틸리티 (프로젝트 루트, 단일 파일)

main.py 가 프로젝트 루트를 sys.path 에 등록하므로, 어떤 점검 파일에서든
경로 접두어 없이 아래처럼 짧게 import 해서 쓴다.

    from common import GOOD, VULN, NA, result, read_text, file_owner_mode_ok

※ 확인팀 도구는 '읽기 전용'이다. 이 모듈에는 시스템을 변경하는 함수를 두지 않는다.
   (설정 변경/조치는 조치팀 저장소가 담당)

[ 상태 상수 ]
    GOOD  "양호"   / VULN "취약" / MANUAL "수동" / NA "N/A" / TODO "미구현"
"""

import glob
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

try:
    import pwd  # Unix 전용
except ImportError:  # pragma: no cover
    pwd = None

# ──────────────────────────────────────────────
# 상태 상수 (main.py 요약이 이 문자열로 집계)
# ──────────────────────────────────────────────
GOOD = "양호"
VULN = "취약"
MANUAL = "수동"
NA = "N/A"
TODO = "미구현"

# 로그인 불가 셸 (비대화형 계정 판별용)
NOLOGIN_SHELLS = {
    "", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin",
    "/bin/nologin", "/usr/bin/false", "/dev/null",
}

# MongoDB 관리자급 역할 / 불필요 계정 의심 패턴 / 설정 경로
MONGOD_CONF = "/etc/mongod.conf"
ADMIN_ROLES = [
    "root", "dbOwner", "userAdmin", "userAdminAnyDatabase",
    "dbAdminAnyDatabase", "readWriteAnyDatabase", "clusterAdmin",
    "clusterManager", "clusterMonitor", "hostManager",
    "backup", "restore", "__system",
]
SUSPICIOUS_PATTERNS = [
    "test", "temp", "sample", "demo", "guest", "default", "example", "dummy",
]


# ──────────────────────────────────────────────
# 결과 생성
# ──────────────────────────────────────────────
def result(code, title, status, detail=""):
    """표준 점검 결과 딕셔너리. 예: return result(CODE, TITLE, GOOD, "정상")"""
    return {"code": code, "title": title, "status": status, "detail": detail}


# ──────────────────────────────────────────────
# 파일 읽기
# ──────────────────────────────────────────────
def read_text(path):
    """파일을 문자열로 읽는다. 실패 시 None (예외 없음)."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def read_lines(path):
    """파일을 줄 리스트로 반환한다. 없으면 빈 리스트."""
    text = read_text(path)
    return [] if text is None else text.splitlines()


# ──────────────────────────────────────────────
# /etc/passwd 파싱
# ──────────────────────────────────────────────
def parse_passwd(path="/etc/passwd"):
    """/etc/passwd 를 파싱해 [{"name","uid","gid","gecos","home","shell"}] 반환."""
    users = []
    for line in read_lines(path):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid, gid = int(parts[2]), int(parts[3])
        except ValueError:
            continue
        users.append({
            "name": parts[0], "uid": uid, "gid": gid,
            "gecos": parts[4], "home": parts[5], "shell": parts[6].strip(),
        })
    return users


def passwd_user(name):
    """특정 사용자 정보를 반환. 없으면 None."""
    for user in parse_passwd():
        if user["name"] == name:
            return user
    return None


# ──────────────────────────────────────────────
# 파일 소유자 / 권한
# ──────────────────────────────────────────────
def owner_name(path):
    """파일 소유자 이름 (pwd 없으면 UID 문자열)."""
    st = os.stat(path)
    if pwd is None:
        return str(st.st_uid)
    try:
        return pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        return str(st.st_uid)


def file_owner_mode_ok(path, owner="root", max_mode=0o640):
    """소유자·권한 기준 충족 여부. Returns (bool, "소유자 x, 권한 y")."""
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    actual = owner_name(path)
    desc = f"소유자 {actual}, 권한 {mode:03o}"
    if actual != owner:
        return False, desc
    if mode > max_mode or mode & stat.S_IWOTH:
        return False, desc
    return True, desc


# ──────────────────────────────────────────────
# 명령 실행
# ──────────────────────────────────────────────
def run_command(args, timeout=3):
    """외부 명령 실행. Returns (returncode, stdout, stderr). 실패 시 (127,"",err)."""
    try:
        done = subprocess.run(
            args, check=False, capture_output=True, text=True, timeout=timeout,
        )
        return done.returncode, done.stdout.strip(), done.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError) as exc:
        return 127, "", str(exc)


def command_exists(name):
    """PATH 에 명령어가 있는지."""
    return shutil.which(name) is not None


# ──────────────────────────────────────────────
# 서비스 상태 (systemd / 프로세스 / 포트 종합)
# ──────────────────────────────────────────────
def systemctl_is_active(*names):
    if not command_exists("systemctl"):
        return False
    for name in names:
        code, out, _ = run_command(["systemctl", "is-active", name])
        if code == 0 and out.strip() == "active":
            return True
    return False


def pgrep_any(*patterns):
    if command_exists("pgrep"):
        for pat in patterns:
            code, _, _ = run_command(["pgrep", "-x", pat])
            if code == 0:
                return True
    proc = Path("/proc")
    if not proc.exists():
        return False
    wanted = set(patterns)
    for comm in proc.glob("[0-9]*/comm"):
        name = read_text(comm)
        if name and name.strip() in wanted:
            return True
    return False


def is_listening_on_port(port):
    for command in (["ss", "-lntup"], ["netstat", "-lntup"]):
        if not command_exists(command[0]):
            continue
        code, out, _ = run_command(command)
        if code == 0 and re.search(rf":{port}\s", out):
            return True
    return False


def ftp_service_active():
    return (
        systemctl_is_active("vsftpd", "proftpd", "pure-ftpd")
        or pgrep_any("vsftpd", "proftpd", "pure-ftpd")
        or is_listening_on_port(21)
    )


def snmp_service_active():
    return systemctl_is_active("snmpd") or pgrep_any("snmpd") or is_listening_on_port(161)


# ──────────────────────────────────────────────
# 기타
# ──────────────────────────────────────────────
def glob_existing(patterns):
    """glob 패턴들에 매칭되는 경로를 중복 제거·정렬해 반환."""
    paths = []
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))


def summarize(items, limit=6):
    """리스트를 "a, b, c 외 N건" 으로 요약."""
    if not items:
        return ""
    head = items[:limit]
    suffix = "" if len(items) <= limit else f" 외 {len(items) - limit}건"
    return ", ".join(head) + suffix


# ──────────────────────────────────────────────
# MongoDB 헬퍼 (읽기 전용) — DBMS(D-xx) 항목에서 사용
# ──────────────────────────────────────────────
def mongo_eval(js_code, user=None, password=None, auth_db="admin",
               auth_mechanism=None, timeout=15):
    """mongosh --eval 실행. Returns (returncode, stdout, stderr).

    인증이 필요한 경우 -u/-p 대신 db.auth()를 사용한다.
    (일부 환경에서 -p 옵션의 특수문자 처리 문제 회피)
    """
    if user and password:
        escaped_user = user.replace("\\", "\\\\").replace('"', '\\"')
        escaped_pass = password.replace("\\", "\\\\").replace('"', '\\"')
        auth_js = f'db.getSiblingDB("{auth_db}").auth("{escaped_user}", "{escaped_pass}");'
        js_code = auth_js + " " + js_code
    cmd = ["mongosh", "--quiet", "--eval", js_code]
    if auth_mechanism:
        cmd += ["--authenticationMechanism", auth_mechanism]
    return run_command(cmd, timeout=timeout)


def mongo_eval_json(js_code, user=None, password=None, auth_db="admin",
                    auth_mechanism=None):
    """mongosh 결과를 JSON 파싱. 실패 시 None. js_code 는 EJSON.stringify 로 출력."""
    code, out, _ = mongo_eval(js_code, user, password, auth_db, auth_mechanism)
    if code != 0:
        return None
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def get_mongod_process_user():
    """mongod 실행 사용자명. 미실행 시 None. (D-07)"""
    code, out, _ = run_command(["ps", "-eo", "user,comm"])
    if code != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "mongod":
            return parts[0]
    return None


def get_bind_ip():
    """mongod.conf 의 net.bindIp 값. 없으면 None. (D-10)"""
    text = read_text(MONGOD_CONF)
    if text is None:
        return None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if s.startswith("bindIp:"):
            return s.split(":", 1)[1].strip().strip('"').strip("'")
    return None


def is_auth_enabled():
    """mongod.conf security.authorization: enabled 여부. (D-01)"""
    text = read_text(MONGOD_CONF)
    if text is None:
        return False
    in_security = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if s == "security:":
            in_security = True
            continue
        if in_security and s.startswith("authorization:"):
            val = s.split(":", 1)[1].strip().strip('"').strip("'")
            return val.lower() == "enabled"
        if in_security and s and not line.startswith((" ", "\t")):
            in_security = False
    return False

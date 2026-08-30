"""
common.py — 조치팀 공통 유틸리티 (프로젝트 루트, 단일 파일)

main.py 가 프로젝트 루트를 sys.path 에 등록하므로, 어떤 조치 파일에서든
경로 접두어 없이 아래처럼 짧게 import 해서 쓴다.

    from common import FIXED, FAILED, MANUAL, result, backup_file, write_text

※ 확인팀(5G_Check_Tool) common.py 의 읽기 헬퍼를 그대로 가져오고,
   여기에 조치(쓰기) 헬퍼를 추가했다. 대상 환경이 같으므로(Ubuntu 22.04 + MongoDB)
   읽기 판정 로직은 확인팀 것과 동일하게 맞춰 재사용한다.

[ 상태 상수 ]
    GOOD    "양호"      — main.py 전용 표시값. fix()가 None을 반환하면(이미 양호) main.py가
                          module.CODE/TITLE로 이 상태의 결과를 합성해 출력·집계에 포함시킨다.
                          fix() 코드에서 직접 반환하는 값이 아니다.
    FIXED   "조치완료"  — 이번 실행에서 취약 상태를 양호로 변경함
    FAILED  "조치실패"  — 조치 시도했지만 실패(권한 부족 등)
    MANUAL  "수동제외"  — 자동 조치 대상이 아님(정책 판단 필요, 스코프 제외)
    TODO    "미구현"    — 아직 작성 전

    fix() 는 이미 양호라고 판단되면 result(...) 대신 None 을 반환한다(이 계약은 변하지 않음).
    main.py 는 None을 받으면 module.CODE/TITLE로 GOOD 상태 결과를 만들어 "양호"로 출력하고
    총 개수·상태별 집계에 포함시킨다(더 이상 완전히 제외하지 않음).
"""

import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

try:
    import pwd
    import grp
except ImportError:  # pragma: no cover
    pwd = grp = None

# ──────────────────────────────────────────────
# 상태 상수 (main.py 요약이 이 문자열로 집계)
# ──────────────────────────────────────────────
GOOD = "양호"
FIXED = "조치완료"
FAILED = "조치실패"
MANUAL = "수동제외"
TODO = "미구현"

NOLOGIN_SHELLS = {
    "", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin",
    "/bin/nologin", "/usr/bin/false", "/dev/null",
}

MONGOD_CONF = "/etc/mongod.conf"
MONGOD_SERVICE = "/lib/systemd/system/mongod.service"
LOCAL_ADDRS = {"127.0.0.1", "::1"}
ALL_ADDRS = {"0.0.0.0", "::", "*"}
ADMIN_ROLES = [
    "root", "dbOwner", "userAdmin", "userAdminAnyDatabase",
    "dbAdminAnyDatabase", "readWriteAnyDatabase", "clusterAdmin",
    "clusterManager", "clusterMonitor", "hostManager",
    "backup", "restore", "__system",
]

BACKUP_DIR = "/var/backups/5g-measure-tool"
_BACKUP_METADATA = {}


# ──────────────────────────────────────────────
# 결과 생성
# ──────────────────────────────────────────────
def result(code, title, status, detail=""):
    """표준 결과 딕셔너리. 예: return result(CODE, TITLE, FIXED, "PermitRootLogin no 로 변경")"""
    return {"code": code, "title": title, "status": status, "detail": detail}


# ──────────────────────────────────────────────
# 파일 읽기 (확인팀 common.py 와 동일)
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
    for user in parse_passwd():
        if user["name"] == name:
            return user
    return None


def owner_name(path):
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


def run_command(args, timeout=3):
    try:
        done = subprocess.run(
            args, check=False, capture_output=True, text=True, timeout=timeout,
        )
        return done.returncode, done.stdout.strip(), done.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError) as exc:
        return 127, "", str(exc)


def command_exists(name):
    return shutil.which(name) is not None


def systemctl_is_active(*names):
    if not command_exists("systemctl"):
        return False
    for name in names:
        code, out, _ = run_command(["systemctl", "is-active", name])
        if code == 0 and out.strip() == "active":
            return True
    return False


def systemctl_is_enabled(name):
    """systemd 부팅 활성화 여부를 확인한다."""
    if not command_exists("systemctl"):
        return False
    code, out, _ = run_command(["systemctl", "is-enabled", name])
    return code == 0 and out.strip() == "enabled"


def capture_service_states(names):
    """서비스별 active/enabled 상태를 조치 전 스냅샷으로 보관한다."""
    return {
        name: {
            "active": systemctl_is_active(name),
            "enabled": systemctl_is_enabled(name),
        }
        for name in dict.fromkeys(names)
    }


def restore_service_states(states):
    """capture_service_states() 결과대로 서비스 상태를 복원한다."""
    errors = []
    if not states:
        return errors
    if not command_exists("systemctl"):
        return ["systemctl 명령을 찾지 못해 서비스 상태 원복 불가"]

    for name, state in states.items():
        enable_action = "enable" if state["enabled"] else "disable"
        code, out, err = run_command(["systemctl", enable_action, name], timeout=30)
        if code != 0:
            errors.append(f"{name}: {enable_action} 원복 실패({err or out or code})")

        active_action = "start" if state["active"] else "stop"
        code, out, err = run_command(["systemctl", active_action, name], timeout=30)
        if code != 0:
            errors.append(f"{name}: {active_action} 원복 실패({err or out or code})")
    return errors


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


def glob_existing(patterns):
    paths = []
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))


def summarize(items, limit=6):
    if not items:
        return ""
    head = items[:limit]
    suffix = "" if len(items) <= limit else f" 외 {len(items) - limit}건"
    return ", ".join(head) + suffix


# ──────────────────────────────────────────────
# 조치(쓰기) 헬퍼 — 확인팀 common.py 에는 없음, 조치팀 전용
# 원칙: 손대기 전에 반드시 backup_file() 로 백업부터 남긴다.
# ──────────────────────────────────────────────
def _has_symlink_component(path):
    """기존 경로 구성요소 중 심볼릭 링크가 있으면 True."""
    candidate = Path(path)
    for component in (candidate, *candidate.parents):
        try:
            if component.is_symlink():
                return True
        except OSError:
            return True
    return False


def safe_path(path, allowed_roots=None, must_exist=False):
    """절대경로·허용 루트·symlink 금지 조건을 검증한다."""
    candidate = Path(path)
    if not candidate.is_absolute() or _has_symlink_component(candidate):
        return False
    if must_exist and not candidate.exists():
        return False
    if allowed_roots:
        try:
            resolved = candidate.resolve(strict=must_exist)
        except OSError:
            return False
        for root in allowed_roots:
            try:
                resolved.relative_to(Path(root).resolve(strict=False))
                break
            except (OSError, ValueError):
                continue
        else:
            return False
    return True


def backup_file(path):
    """조치 전 원본을 BACKUP_DIR 에 타임스탬프 붙여 복사. 백업 경로 반환(실패 시 None)."""
    src = Path(path)
    if not src.exists() or not safe_path(src, must_exist=True):
        return None
    try:
        if not stat.S_ISREG(src.lstat().st_mode):
            return None
        os.makedirs(BACKUP_DIR, exist_ok=True)
        if _has_symlink_component(BACKUP_DIR):
            return None
        # Prevent same-basename and same-second backups from overwriting each other.
        identity = hashlib.sha256(
            str(src.resolve()).encode("utf-8")
        ).hexdigest()[:12]
        dest = Path(BACKUP_DIR) / f"{src.name}.{identity}.{time.time_ns()}.bak"
        source_stat = src.stat()
        shutil.copy2(src, dest)
        _BACKUP_METADATA[str(dest)] = {
            "source": str(src),
            "mode": stat.S_IMODE(source_stat.st_mode),
            "uid": source_stat.st_uid,
            "gid": source_stat.st_gid,
        }
        return str(dest)
    except (PermissionError, OSError):
        return None


def restore_backups(backups):
    """현재 실행에서 만든 백업을 역순으로 원위치하고 오류 목록을 반환한다."""
    errors = []
    for backup in reversed(backups):
        metadata = _BACKUP_METADATA.get(str(backup))
        if metadata is None:
            errors.append(f"{backup}: 원본 경로 메타데이터 없음")
            continue
        try:
            source = metadata["source"]
            if not safe_path(source):
                errors.append(f"{source}: 안전하지 않은 원본 경로로 원복 거부")
                continue
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(source, flags, metadata["mode"])
            with open(backup, "rb") as input_file, os.fdopen(fd, "wb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            os.chmod(metadata["source"], metadata["mode"])
            if hasattr(os, "chown"):
                os.chown(metadata["source"], metadata["uid"], metadata["gid"])
        except (PermissionError, OSError) as exc:
            errors.append(f"{metadata['source']}: 원복 실패({exc})")
    return errors


def write_text(path, content, dry_run=False):
    """파일 전체를 덮어쓴다. dry_run=True 면 쓰지 않고 True만 반환(사전 확인용)."""
    if dry_run:
        return True
    try:
        target = Path(path)
        if not safe_path(target):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        return True
    except (PermissionError, OSError):
        return False


def replace_or_append_line(path, pattern, new_line, dry_run=False):
    """
    파일에서 정규식 pattern 에 매칭되는 줄을 new_line 으로 치환한다.
    매칭되는 줄이 없으면 파일 끝에 new_line 을 추가한다.
    조치 전 backup_file() 로 백업하는 것을 전제로 한다(이 함수는 백업하지 않음).
    Returns (bool changed, str reason).
    """
    lines = read_lines(path)
    regex = re.compile(pattern)
    matched = False
    out_lines = []
    for line in lines:
        if regex.search(line):
            matched = True
            out_lines.append(new_line)
        else:
            out_lines.append(line)
    if not matched:
        out_lines.append(new_line)

    new_content = "\n".join(out_lines) + "\n"
    if dry_run:
        return True, "dry-run: 변경 예정"
    ok = write_text(path, new_content)
    return ok, ("변경됨" if ok else "쓰기 실패")


def set_file_mode(path, mode, dry_run=False):
    """8진수 mode(int, 예: 0o600)로 권한 변경. Returns bool."""
    if dry_run:
        return True
    try:
        os.chmod(path, mode)
        return True
    except (PermissionError, OSError):
        return False


def set_file_owner(path, owner, group=None, dry_run=False):
    """소유자(및 선택적으로 그룹) 변경. 이름 문자열로 받는다. Returns bool."""
    if pwd is None:
        return False
    if dry_run:
        return True
    try:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid if group else -1
        os.chown(path, uid, gid)
        return True
    except (KeyError, PermissionError, OSError):
        return False


def systemctl_restart(name, dry_run=False):
    """서비스 재시작. Returns (bool ok, str detail)."""
    if dry_run:
        return True, "dry-run: 재시작 예정"
    code, out, err = run_command(["systemctl", "restart", name], timeout=15)
    return code == 0, (err or out or f"exit={code}")


# ──────────────────────────────────────────────
# MongoDB 헬퍼 (읽기 + 조치) — DBMS(D-xx) 항목에서 사용
# 자격 증명은 명령행에 남기지 말고 mongo_eval() 인자로만 전달한다.
# ──────────────────────────────────────────────
def mongo_eval(js_code, user=None, password=None, auth_db="admin",
               auth_mechanism=None, timeout=15):
    cmd = ["mongosh", "--quiet", "--eval", js_code]
    if user and password:
        cmd += ["-u", user, "-p", password, "--authenticationDatabase", auth_db]
    if auth_mechanism:
        cmd += ["--authenticationMechanism", auth_mechanism]
    return run_command(cmd, timeout=timeout)


def mongo_eval_json(js_code, user=None, password=None, auth_db="admin",
                    auth_mechanism=None):
    code, out, _ = mongo_eval(js_code, user, password, auth_db, auth_mechanism)
    if code != 0:
        return None
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def get_bind_ip():
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


# ──────────────────────────────────────────────
# mongod 프로세스/서비스 파일 조회 (D-07 등에서 사용)
# ──────────────────────────────────────────────
def get_mongod_process_user():
    """실행 중인 mongod 프로세스의 사용자를 반환한다. 없으면 None."""
    code, out, _ = run_command(["ps", "-eo", "user,comm"])
    if code != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "mongod":
            return parts[0]
    return None


def get_service_file_user():
    """systemd 서비스 유닛 파일의 User= 값을 반환한다. 없으면 None."""
    text = read_text(MONGOD_SERVICE)
    if text is None:
        return None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("User="):
            return s.split("=", 1)[1].strip()
    return None


def restart_mongod(dry_run=False):
    """daemon-reload 후 mongod 재시작. Returns (bool ok, str detail)."""
    if dry_run:
        return True, "dry-run: daemon-reload + 재시작 예정"
    run_command(["systemctl", "daemon-reload"])
    code, out, err = run_command(["systemctl", "restart", "mongod"], timeout=30)
    return code == 0, (err or out or f"exit={code}")


# ──────────────────────────────────────────────
# mongod.conf 섹션 단위 최소 변경 쓰기 (D-08/D-10 등에서 사용)
# ──────────────────────────────────────────────
def set_conf_scalar(text, section, key, value):
    """
    <section>: 블록 아래 <key>: <value> 줄만 최소 변경으로 설정한다(다른 줄/주석 보존).
    section/key 블록이 없으면 새로 추가한다.
    """
    lines = text.splitlines()
    section_header = f"{section}:"

    section_start = None
    for idx, line in enumerate(lines):
        if len(line) - len(line.lstrip(" ")) != 0:
            continue
        stripped = line.rstrip()
        if stripped == section_header or stripped.startswith(section_header + " ") \
                or stripped.startswith(section_header + "\t"):
            section_start = idx
            break

    if section_start is None:
        new_lines = list(lines)
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines.append(section_header)
        new_lines.append(f"  {key}: {value}")
        return "\n".join(new_lines) + "\n"

    section_end = len(lines)
    for idx in range(section_start + 1, len(lines)):
        line = lines[idx]
        if not line.strip():
            continue
        if len(line) - len(line.lstrip(" ")) == 0:
            section_end = idx
            break

    key_pattern = re.compile(rf"^(\s+){re.escape(key)}\s*:\s*(.*)$")
    key_line_idx = None
    key_indent = "  "
    for idx in range(section_start + 1, section_end):
        m = key_pattern.match(lines[idx])
        if m:
            key_line_idx = idx
            key_indent = m.group(1)
            break

    new_lines = list(lines)
    if key_line_idx is not None:
        new_lines[key_line_idx] = f"{key_indent}{key}: {value}"
    else:
        new_lines.insert(section_start + 1, f"  {key}: {value}")

    return "\n".join(new_lines) + "\n"


def get_net_config():
    """mongod.conf의 net 섹션을 읽어 {"bind_ip": [...], "bind_ip_all": bool, "port": int} 반환. 실패 시 None."""
    text = read_text(MONGOD_CONF)
    if text is None:
        return None
    lines = text.splitlines()
    in_net = False
    bind_ip_raw, bind_ip_all, port = None, False, 27017
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if len(line) - len(line.lstrip(" ")) == 0:
            in_net = stripped == "net:"
            continue
        if not in_net:
            continue
        if stripped.startswith("bindIp:"):
            bind_ip_raw = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        elif stripped.startswith("bindIpAll:"):
            bind_ip_all = stripped.split(":", 1)[1].strip().lower() == "true"
        elif stripped.startswith("port:"):
            try:
                port = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass
    bind_ip = [ip.strip() for ip in bind_ip_raw.split(",") if ip.strip()] if bind_ip_raw else []
    return {"bind_ip": bind_ip, "bind_ip_all": bind_ip_all, "port": port}


# ──────────────────────────────────────────────
# 실제 리스닝 주소 / 방화벽 조회 (D-10에서 사용)
# ──────────────────────────────────────────────
def get_listening_addresses(port):
    """포트에서 실제 리스닝 중인 로컬 주소 목록. 확인 불가 시 None."""
    for args in (["ss", "-H", "-ltnp"], ["ss", "-H", "-ltn"], ["netstat", "-ltnp"], ["netstat", "-ltn"]):
        if not command_exists(args[0]):
            continue
        code, out, _ = run_command(args, timeout=5)
        if code != 0:
            continue
        addrs = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            addr, _, lport = local.rpartition(":")
            if lport != str(port):
                continue
            addrs.append(addr.strip("[]"))
        return addrs
    return None


def classify_bind_scope(addrs):
    """"none" / "local" / "external" / "all" 로 분류한다."""
    if not addrs:
        return "none"
    addr_set = set(addrs)
    if addr_set & ALL_ADDRS:
        return "all"
    if addr_set - LOCAL_ADDRS:
        return "external"
    return "local"


def get_firewall_rules():
    """Returns (tool, ok, raw_text). tool: ufw/firewalld/nft/iptables/None. 읽기 전용, 상태 변경 없음."""
    checks = (
        ("ufw", ["ufw", "status", "verbose"]),
        ("firewalld", ["firewall-cmd", "--list-all"]),
        ("nft", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables", "-L", "INPUT", "-n"]),
    )
    for tool, args in checks:
        if not command_exists(tool):
            continue
        code, out, _ = run_command(args, timeout=5)
        if code == 0 and out:
            return tool, True, out
    return None, False, ""


def firewall_port_open_to_any(tool, raw_text, port):
    """True: 무제한 허용 / False: 특정 IP·CIDR로 제한 / None: 판단 불가."""
    if tool == "ufw":
        pattern = re.compile(
            rf"^{port}(?:/tcp)?(?:\s*\(v6\))?\s+ALLOW(?:\s+IN)?\s+(.+)$",
            re.MULTILINE | re.IGNORECASE,
        )
        matches = pattern.findall(raw_text)
        if not matches:
            return None
        for source in matches:
            if source.strip().lower() in ("anywhere", "anywhere (v6)", "0.0.0.0/0", "::/0"):
                return True
        return False
    return None

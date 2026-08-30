"""U-11 사용자 Shell 점검 조치."""

from fix_common import (
    FIXED,
    FAILED,
    MANUAL,
    NOLOGIN_SHELLS,
    result,
    parse_passwd,
    backup_file,
    command_exists,
    run_command,
    summarize,
)


CODE = "U-11"
TITLE = "사용자 Shell 점검"
TARGET = "/etc/passwd"

# KISA 예시 계정과 Ubuntu/Open5GS/MongoDB의 대표 서비스 계정만 자동 조치한다.
# UID만 보고 모든 계정을 잠그면 운영용 관리 계정까지 차단할 수 있다.
AUTO_ACCOUNTS = {
    "daemon", "bin", "sys", "adm", "listen", "nobody", "nobody4",
    "noaccess", "diag", "operator", "games", "gopher", "man", "lp",
    "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
    "irc", "gnats", "systemd-network", "systemd-resolve",
    "systemd-timesync", "messagebus", "syslog", "_apt", "tss",
    "uuidd", "tcpdump", "sshd", "landscape", "pollinate",
    "open5gs", "mongodb",
}


def _login_system_users():
    return [
        user for user in parse_passwd()
        if user["name"] != "root"
        and user["uid"] < 1000
        and user["shell"] not in NOLOGIN_SHELLS
        and user["shell"] not in {"/bin/sync", "/sbin/halt", "/sbin/shutdown"}
    ]


def fix(dry_run=False):
    bad = _login_system_users()
    if not bad:
        return None

    # root와 UID 0을 공유하는 비-root 계정은 로그인 허용 사유가 없으므로
    # 이름이 허용 목록에 없어도 우선 nologin을 적용한다.
    unknown = [
        user["name"] for user in bad
        if user["name"] not in AUTO_ACCOUNTS and user["uid"] != 0
    ]
    if unknown:
        return result(
            CODE,
            TITLE,
            MANUAL,
            "로그인 필요 여부 확인 후 AUTO_ACCOUNTS에 추가 필요: "
            + summarize(unknown),
        )

    if not command_exists("usermod"):
        return result(CODE, TITLE, FAILED, "usermod 명령을 찾을 수 없음")

    shell = "/usr/sbin/nologin"
    targets = [user["name"] for user in bad]
    if dry_run:
        return result(
            CODE,
            TITLE,
            FIXED,
            "dry-run: 로그인 셸을 /usr/sbin/nologin으로 변경 예정: "
            + summarize(targets),
        )

    backup = backup_file(TARGET)
    if backup is None:
        return result(CODE, TITLE, FAILED, f"{TARGET} 백업 실패")

    old_shells = {user["name"]: user["shell"] for user in bad}
    changed = []
    for name in targets:
        code, output, error = run_command(
            ["usermod", "-s", shell, name], timeout=15
        )
        if code != 0:
            for changed_name in reversed(changed):
                run_command(
                    ["usermod", "-s", old_shells[changed_name], changed_name],
                    timeout=15,
                )
            return result(
                CODE,
                TITLE,
                FAILED,
                f"{name} 셸 변경 실패, 변경 계정 복원: {error or output}",
            )
        changed.append(name)

    remaining = _login_system_users()
    if remaining:
        for changed_name in reversed(changed):
            run_command(
                ["usermod", "-s", old_shells[changed_name], changed_name],
                timeout=15,
            )
        return result(CODE, TITLE, FAILED, "셸 변경 검증 실패로 원래 셸 복원")

    return result(
        CODE,
        TITLE,
        FIXED,
        "/usr/sbin/nologin 적용: " + summarize(targets) + f"; 백업: {backup}",
    )

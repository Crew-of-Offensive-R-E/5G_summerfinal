"""U-63 sudo 명령어 접근 관리"""
import os
import stat

from check_common import GOOD, VULN, result

CODE = "U-63"
TITLE = "sudo 명령어 접근 관리"

SUDOERS = "/etc/sudoers"
SUDOERS_D = "/etc/sudoers.d"


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _is_root_owned(path):
    st = os.stat(path)
    return st.st_uid == 0 and st.st_gid == 0


def _sudo_file_ok(path):
    if not _is_root_owned(path):
        return False
    mode = _mode(path)
    return mode in {0o400, 0o440, 0o600, 0o640}


def _sudo_dir_ok(path):
    if not _is_root_owned(path):
        return False
    mode = _mode(path)
    return (mode & 0o007) == 0


def check():
    problems = []

    if not os.path.exists(SUDOERS):
        problems.append(f"{SUDOERS} 파일 없음")
    elif not _sudo_file_ok(SUDOERS):
        problems.append(f"{SUDOERS} 소유자/권한 부적절({_mode(SUDOERS):03o})")

    if os.path.isdir(SUDOERS_D):
        if not _sudo_dir_ok(SUDOERS_D):
            problems.append(f"{SUDOERS_D} 디렉터리 권한 부적절({_mode(SUDOERS_D):03o})")

        for root, _, files in os.walk(SUDOERS_D):
            for filename in files:
                path = os.path.join(root, filename)
                if not _sudo_file_ok(path):
                    problems.append(f"{path} 소유자/권한 부적절({_mode(path):03o})")

    if not problems:
        return result(CODE, TITLE, GOOD, "/etc/sudoers 및 sudoers.d 권한이 안전합니다.")

    return result(CODE, TITLE, VULN, "sudoers 접근 권한 설정 미흡: " + ", ".join(problems))

from check_common import MANUAL, result, read_text


CODE = "U-08"
TITLE = "관리자 그룹에 최소한의 계정 포함"


def check():
    group = read_text("/etc/group") or ""
    root_line = next((line for line in group.splitlines() if line.startswith("root:")), "root 그룹 확인 불가")
    return result(CODE, TITLE, MANUAL, f"root 그룹 구성원 필요성 수동 확인: {root_line}")

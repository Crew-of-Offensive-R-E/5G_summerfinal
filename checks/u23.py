from check_common import GOOD, MANUAL, NA, result, run_command


CODE = "U-23"
TITLE = "SUID, SGID, Sticky bit 점검"
def check():
    code, stdout, stderr = run_command(["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"], timeout=30)
    if code == 127:
        return result(CODE, TITLE, NA, f"find 실행 불가: {stderr}")
    found = [line.strip() for line in stdout.splitlines() if line.strip()]
    if found:
        return result(CODE, TITLE, MANUAL, "SUID/SGID 파일 - 업무 필요성 및 OS/응용프로그램 정상 작동 여부 수동 확인 필요: " + ", ".join(found[:10]))
    return result(CODE, TITLE, GOOD, "SUID/SGID 파일 없음")

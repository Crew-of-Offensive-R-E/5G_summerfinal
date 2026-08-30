from check_common import GOOD, VULN, NA, result, run_command


CODE = "U-26"
TITLE = "/dev에 존재하지 않는 device 파일 점검"


def check():
    code, stdout, stderr = run_command(["find", "/dev", "-type", "f", "-print"], timeout=10)
    if code == 127:
        return result(CODE, TITLE, NA, f"find 실행 불가: {stderr}")
    files = [line.strip() for line in stdout.splitlines() if line.strip()]
    return result(CODE, TITLE, GOOD if not files else VULN, "일반 파일: " + (", ".join(files[:10]) if files else "없음"))

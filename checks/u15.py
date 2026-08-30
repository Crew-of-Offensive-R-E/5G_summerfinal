from check_common import GOOD, VULN, NA, result, run_command, summarize


CODE = "U-15"
TITLE = "파일 및 디렉터리 소유자 설정"

# 컨테이너/스냅샷 이미지 레이어 — 호스트 UID와 매핑 안 되는 게 정상
_PRUNE_PATHS = [
    "/var/lib/containerd",
    "/var/lib/docker",
    "/var/lib/snapd",
]


def check():
    cmd = ["find", "/", "-xdev"]
    for p in _PRUNE_PATHS:
        cmd += ["-path", p, "-prune", "-o"]
    cmd += ["(", "-nouser", "-o", "-nogroup", ")", "-print"]
    code, stdout, stderr = run_command(cmd, timeout=30)
    if code == 127:
        return result(CODE, TITLE, NA, f"find 실행 불가: {stderr}")
    paths = [l for l in stdout.strip().splitlines() if l]
    if paths:
        return result(CODE, TITLE, VULN, "소유자 또는 그룹 없는 파일 발견: " + summarize(paths))
    return result(CODE, TITLE, GOOD, "소유자/그룹 없는 파일 미발견")

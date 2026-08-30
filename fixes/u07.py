"""U-07 불필요한 계정 제거 - 정책 확인이 필요한 수동 조치 항목."""

from fix_common import MANUAL, result, parse_passwd, NOLOGIN_SHELLS, summarize


CODE = "U-07"
TITLE = "불필요한 계정 제거"
PROTECTED_ACCOUNTS = {
    "root",
    "nobody",
    "ubuntu",
    "open5gs",
    "mongodb",
}
LEGACY_ACCOUNTS = {"lp", "uucp", "nuucp", "games", "news"}


def _candidates():
    candidates = []
    for user in parse_passwd():
        name = user["name"]
        if name in PROTECTED_ACCOUNTS:
            continue
        login_capable = user["shell"] not in NOLOGIN_SHELLS
        if name in LEGACY_ACCOUNTS or (user["uid"] >= 1000 and login_capable):
            candidates.append(name)
    return sorted(set(candidates))


def fix(dry_run=False):
    candidates = _candidates()
    if not candidates:
        return None
    prefix = "dry-run: " if dry_run else ""
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "업무·서비스 사용 여부 확인 후 userdel 대상 결정 필요: "
        + summarize(candidates),
    )


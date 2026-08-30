"""U-08 관리자 그룹에 최소한의 계정 포함 - 정책 확인 항목."""

import grp

from fix_common import MANUAL, result, summarize


CODE = "U-08"
TITLE = "관리자 그룹에 최소한의 계정 포함"


def fix(dry_run=False):
    try:
        root_group = grp.getgrnam("root")
    except KeyError:
        return result(CODE, TITLE, MANUAL, "root 그룹이 없어 계정 정책 확인 필요")

    members = sorted(set(name for name in root_group.gr_mem if name != "root"))
    if not members:
        return None

    prefix = "dry-run: " if dry_run else ""
    return result(
        CODE,
        TITLE,
        MANUAL,
        prefix
        + "root 그룹 등록 목적 확인 후 불필요한 계정만 gpasswd -d로 제거 필요: "
        + summarize(members),
    )


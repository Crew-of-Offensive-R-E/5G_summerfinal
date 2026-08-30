#!/usr/bin/env python3
"""
5G_summerfinal — KISA 취약점 점검 + 자동 조치 통합 도구

파이프라인:
  1단계(점검)   checks/ 모듈 전체 실행 → 양호/취약/수동/N/A 판정
  2단계(조치)   취약 항목만 fixes/ 모듈의 fix() 실행 → 조치완료/조치실패/수동제외
  3단계(재검증) 조치된 항목만 checks/ 재실행 → 양호 전환 확인

실행:
    sudo python3 main.py -u admin -p 'password'           # 전체 파이프라인
    sudo python3 main.py -u admin -p 'password' --check    # 1단계(점검)만
    sudo python3 main.py -u admin -p 'password' --fix      # 2단계(조치)만
    sudo python3 main.py --only U-01 U-02                   # 특정 항목만
    sudo python3 main.py --dry-run                          # 조치 시 실제 변경 없이 예정 동작만 출력
    sudo python3 main.py --save results/report.txt          # 결과 파일 저장
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import argparse
import datetime
import importlib
import inspect
import pkgutil

import checks as checks_pkg
import fixes as fixes_pkg
from check_common import GOOD, VULN, MANUAL, NA, TODO


# ── 상수 ──
FIXED = "조치완료"
FAILED = "조치실패"
FIX_MANUAL = "수동제외"


# ── 모듈 로딩 ──

def load_modules(package, entry_func, only=None):
    """패키지에서 entry_func(check 또는 fix)을 가진 모듈을 자동 수집."""
    only_norm = {o.lower().replace("-", "") for o in only} if only else None
    modules = []
    for _, name, _ in pkgutil.iter_modules(package.__path__):
        if only_norm is not None and name.lower() not in only_norm:
            continue
        module = importlib.import_module(f"{package.__name__}.{name}")
        if hasattr(module, entry_func):
            modules.append(module)
    modules.sort(key=lambda m: m.__name__)
    return modules


def run_check(module, user=None, password=None):
    """check() 시그니처에 user/password가 있으면 인증 정보를 넘긴다."""
    params = inspect.signature(module.check).parameters
    if "user" in params and "password" in params:
        return module.check(user=user, password=password)
    return module.check()


def run_fix(module, user=None, password=None, dry_run=False):
    """fix() 시그니처를 보고 필요한 인자만 넘긴다."""
    params = inspect.signature(module.fix).parameters
    kwargs = {}
    if "user" in params and "password" in params:
        kwargs.update(user=user, password=password)
    if "dry_run" in params:
        kwargs["dry_run"] = dry_run
    return module.fix(**kwargs)


def code_to_modname(code):
    """U-01 → u01, D-10 → d10"""
    return code.lower().replace("-", "")


# ── 출력 헬퍼 ──

def print_line(code, status, title, detail=""):
    line = f"[{code}] {status:<6} {title}"
    print(line)
    lines = [line]
    if detail:
        d = f"        {detail}"
        print(d)
        lines.append(d)
    return lines


# ── 메인 ──

def main():
    parser = argparse.ArgumentParser(
        description="5G SA 코어 네트워크 취약점 점검 + 자동 조치 통합 도구")
    parser.add_argument("-u", "--user", help="MongoDB 인증 사용자")
    parser.add_argument("-p", "--password", help="MongoDB 인증 비밀번호")
    parser.add_argument("--only", nargs="+", metavar="CODE",
                        help="특정 항목만 실행 (예: --only U-01 D-10)")
    parser.add_argument("--check", action="store_true",
                        help="1단계(점검)만 실행")
    parser.add_argument("--fix", action="store_true",
                        help="2단계(조치)만 실행 (점검 건너뜀)")
    parser.add_argument("--dry-run", action="store_true",
                        help="조치 시 실제 변경 없이 예정 동작만 출력")
    parser.add_argument("--save", metavar="PATH", help="결과를 텍스트 파일로 저장")
    args = parser.parse_args()

    all_lines = []
    user, password = args.user, args.password

    # ================================================================
    # 1단계: 점검 (확인팀 코드)
    # ================================================================
    check_results = []
    vuln_codes = []

    if not args.fix:
        print("\n" + "=" * 60)
        print("  1단계: 취약점 점검 (확인팀)")
        print("=" * 60)
        all_lines.append("=" * 60)
        all_lines.append("  1단계: 취약점 점검 (확인팀)")
        all_lines.append("=" * 60)

        for module in load_modules(checks_pkg, "check", only=args.only):
            try:
                r = run_check(module, user=user, password=password)
                check_results.append(r)
                lines = print_line(r["code"], r["status"], r["title"], r.get("detail", ""))
                all_lines.extend(lines)
                if r["status"] == VULN:
                    vuln_codes.append(r["code"])
            except Exception as exc:
                code = getattr(module, "CODE", module.__name__)
                line = f"[{code}] 오류   {exc}"
                print(line)
                all_lines.append(line)

        def cnt(status):
            return sum(1 for r in check_results if r.get("status") == status)

        summary = (
            f"\n총 {len(check_results)}개 | "
            f"양호 {cnt(GOOD)} | 취약 {cnt(VULN)} | "
            f"수동 {cnt(MANUAL)} | N/A {cnt(NA)}"
        )
        print(summary)
        all_lines.append(summary)

        if args.check:
            # --check 모드면 여기서 종료
            _save_report(args.save, all_lines)
            sys.exit(1 if cnt(VULN) else 0)

    # ================================================================
    # 2단계: 취약 항목 조치 (조치팀 코드)
    # ================================================================
    if args.fix:
        # --fix 모드: 전체 fix 모듈 실행
        fix_targets = None  # 전부
    else:
        fix_targets = vuln_codes
        if not fix_targets:
            print("\n취약 항목이 없어 조치를 건너뜁니다.")
            all_lines.append("\n취약 항목이 없어 조치를 건너뜁니다.")
            _save_report(args.save, all_lines)
            sys.exit(0)

    print("\n" + "=" * 60)
    print("  2단계: 취약 항목 자동 조치 (조치팀)")
    print("=" * 60)
    all_lines.append("")
    all_lines.append("=" * 60)
    all_lines.append("  2단계: 취약 항목 자동 조치 (조치팀)")
    all_lines.append("=" * 60)

    # fix 모듈 로딩 — 취약 코드에 해당하는 것만
    if fix_targets is not None:
        fix_only = [code_to_modname(c) for c in fix_targets]
    else:
        fix_only = [code_to_modname(c) for c in args.only] if args.only else None

    fix_results = []
    fixed_codes = []

    for module in load_modules(fixes_pkg, "fix", only=fix_only):
        code = getattr(module, "CODE", module.__name__)
        try:
            r = run_fix(module, user=user, password=password, dry_run=args.dry_run)
            if r is None:
                r = {"code": code, "title": getattr(module, "TITLE", ""),
                     "status": GOOD, "detail": "이미 양호"}
            fix_results.append(r)
            lines = print_line(r["code"], r["status"], r["title"], r.get("detail", ""))
            all_lines.extend(lines)
            if r["status"] == FIXED:
                fixed_codes.append(r["code"])
        except Exception as exc:
            line = f"[{code}] 오류   {exc}"
            print(line)
            all_lines.append(line)

    def fix_cnt(status):
        return sum(1 for r in fix_results if r.get("status") == status)

    fix_summary = (
        f"\n조치 결과: 조치완료 {fix_cnt(FIXED)} | "
        f"조치실패 {fix_cnt(FAILED)} | 수동제외 {fix_cnt(FIX_MANUAL)} | "
        f"이미양호 {fix_cnt(GOOD)}"
    )
    print(fix_summary)
    all_lines.append(fix_summary)

    if args.dry_run:
        print("(dry-run: 실제 변경 없음)")
        all_lines.append("(dry-run: 실제 변경 없음)")

    # ================================================================
    # 3단계: 재검증 (조치된 항목만 확인팀 코드 재실행)
    # ================================================================
    if fixed_codes and not args.dry_run:
        print("\n" + "=" * 60)
        print("  3단계: 조치 항목 재검증 (확인팀)")
        print("=" * 60)
        all_lines.append("")
        all_lines.append("=" * 60)
        all_lines.append("  3단계: 조치 항목 재검증 (확인팀)")
        all_lines.append("=" * 60)

        verify_only = [code_to_modname(c) for c in fixed_codes]
        verified = 0
        failed_verify = 0

        for module in load_modules(checks_pkg, "check", only=verify_only):
            try:
                r = run_check(module, user=user, password=password)
                status_mark = "✓ 양호" if r["status"] == GOOD else "✗ " + r["status"]
                lines = print_line(r["code"], status_mark, r["title"], r.get("detail", ""))
                all_lines.extend(lines)
                if r["status"] == GOOD:
                    verified += 1
                else:
                    failed_verify += 1
            except Exception as exc:
                code = getattr(module, "CODE", module.__name__)
                line = f"[{code}] 오류   {exc}"
                print(line)
                all_lines.append(line)
                failed_verify += 1

        verify_summary = f"\n재검증: {verified}건 양호 전환 확인, {failed_verify}건 미전환"
        print(verify_summary)
        all_lines.append(verify_summary)

    # ================================================================
    # 최종 요약
    # ================================================================
    print("\n" + "=" * 60)
    print("  최종 요약")
    print("=" * 60)

    if check_results:
        before_vuln = sum(1 for r in check_results if r["status"] == VULN)
        after_vuln = before_vuln - len(fixed_codes)
        if after_vuln < 0:
            after_vuln = 0
        final = (
            f"점검 항목: {len(check_results)}개\n"
            f"조치 전 취약: {before_vuln}건 → 조치 후 취약: {after_vuln}건\n"
            f"조치 완료: {len(fixed_codes)}건"
        )
    else:
        final = f"조치 실행: {len(fix_results)}건"

    print(final)
    all_lines.append("")
    all_lines.append("=" * 60)
    all_lines.append("  최종 요약")
    all_lines.append("=" * 60)
    all_lines.append(final)

    _save_report(args.save, all_lines)


def _save_report(path, lines):
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    header = f"# 5G_summerfinal 점검+조치 결과 {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(header + "\n" + "\n".join(lines) + "\n")
    print(f"\n결과 저장: {path}")


if __name__ == "__main__":
    main()

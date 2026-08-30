"""U-50 DNS Zone Transfer를 허용되지 않은 호스트에서 차단하는 조치."""

import os
import posixpath

from fix_common import (
    FAILED,
    FIXED,
    MANUAL,
    backup_file,
    command_exists,
    read_text,
    result,
    restore_backups,
    run_command,
    safe_path,
    summarize,
    systemctl_is_active,
    write_text,
)
from server_policy import (
    PolicyError,
    policy_for,
    require_choice,
    require_string_list,
)


CODE = "U-50"
TITLE = "DNS Zone Transfer 설정"

NAMED_CONFIGS = (
    "/etc/bind/named.conf",
    "/etc/bind/named.conf.options",
    "/etc/named.conf",
)

OPTIONS_TARGETS = (
    "/etc/bind/named.conf.options",
    "/etc/bind/named.conf",
    "/etc/named.conf",
)


class _ConfigParseError(ValueError):
    pass


def _tokenize(content):
    """주석과 문자열을 구분하는 최소 BIND 토크나이저."""
    tokens = []
    index = 0
    length = len(content)
    punctuation = "{};!"

    while index < length:
        char = content[index]
        if char.isspace():
            index += 1
            continue
        if char == "#" or content.startswith("//", index):
            newline = content.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue
        if content.startswith("/*", index):
            end = content.find("*/", index + 2)
            if end < 0:
                raise _ConfigParseError("종료되지 않은 /* 주석")
            index = end + 2
            continue
        if char == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                current = content[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    index += 1
                    break
                index += 1
            else:
                raise _ConfigParseError("종료되지 않은 문자열")
            raw = content[start:index]
            value = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            tokens.append({"value": value, "kind": "string", "start": start, "end": index})
            continue
        if char in punctuation:
            tokens.append({"value": char, "kind": "punct", "start": index, "end": index + 1})
            index += 1
            continue

        start = index
        while index < length:
            current = content[index]
            if current.isspace() or current in punctuation or current == "#":
                break
            if content.startswith("//", index) or content.startswith("/*", index):
                break
            index += 1
        if index == start:
            index += 1
            continue
        tokens.append({
            "value": content[start:index],
            "kind": "word",
            "start": start,
            "end": index,
        })
    return tokens


def _is_statement_start(tokens, index):
    return index == 0 or tokens[index - 1]["value"] in ("{", ";")


def _scan_config(content):
    tokens = _tokenize(content)
    pairs = {}
    stack = []
    depths = []
    depth = 0

    for index, token in enumerate(tokens):
        value = token["value"]
        if value == "}":
            depth -= 1
            if depth < 0 or not stack:
                raise _ConfigParseError("짝이 맞지 않는 닫는 중괄호")
            open_index = stack.pop()
            pairs[open_index] = index
        depths.append(depth)
        if value == "{":
            stack.append(index)
            depth += 1
    if stack:
        raise _ConfigParseError("짝이 맞지 않는 여는 중괄호")

    options_blocks = []
    for index, token in enumerate(tokens):
        if token["kind"] != "word" or token["value"].lower() != "options":
            continue
        if not _is_statement_start(tokens, index) or depths[index] != 0:
            continue
        open_index = index + 1
        if open_index < len(tokens) and tokens[open_index]["value"] == "{":
            options_blocks.append({
                "start": token["start"],
                "open": open_index,
                "close": pairs[open_index],
                "open_end": tokens[open_index]["end"],
                "depth": depths[open_index],
            })

    allow_statements = []
    for index, token in enumerate(tokens):
        if token["kind"] != "word" or token["value"].lower() != "allow-transfer":
            continue
        if not _is_statement_start(tokens, index):
            continue

        open_index = index + 1
        while open_index < len(tokens) and tokens[open_index]["value"] not in ("{", ";", "}"):
            open_index += 1
        if open_index >= len(tokens) or tokens[open_index]["value"] != "{":
            raise _ConfigParseError("allow-transfer 블록 형식을 해석할 수 없음")
        close_index = pairs[open_index]
        semicolon = close_index + 1
        if semicolon >= len(tokens) or tokens[semicolon]["value"] != ";":
            raise _ConfigParseError("allow-transfer 블록 종결 세미콜론 누락")

        body_words = [
            body_token["value"].lower()
            for body_token in tokens[open_index + 1:close_index]
            if body_token["kind"] in {"word", "string"}
        ]
        has_positive_any = "any" in body_words
        is_none_only = body_words == ["none"]

        is_global = any(
            block["open"] < index < block["close"]
            and depths[index] == block["depth"] + 1
            for block in options_blocks
        )
        allow_statements.append({
            "start": token["start"],
            "end": tokens[semicolon]["end"],
            "line": content.count("\n", 0, token["start"]) + 1,
            "has_positive_any": has_positive_any,
            "is_none_only": is_none_only,
            "is_global": is_global,
        })

    includes = []
    for index, token in enumerate(tokens):
        if token["kind"] != "word" or token["value"].lower() != "include":
            continue
        if not _is_statement_start(tokens, index):
            continue
        if index + 2 >= len(tokens):
            raise _ConfigParseError("include 문 형식을 해석할 수 없음")
        path_token = tokens[index + 1]
        end_token = tokens[index + 2]
        if path_token["kind"] != "string" or end_token["value"] != ";":
            raise _ConfigParseError("include 문 형식을 해석할 수 없음")
        includes.append(path_token["value"])

    return {
        "options_blocks": options_blocks,
        "allow_statements": allow_statements,
        "includes": includes,
    }


def _load_configs():
    configs = {}
    scans = {}
    errors = []
    visited = set()

    def visit(path, required=False):
        normalized = posixpath.normpath(path)
        if normalized in visited:
            return
        visited.add(normalized)
        content = read_text(normalized)
        if content is None:
            if required or os.path.exists(normalized):
                errors.append(f"{normalized}: 설정 파일 읽기 실패")
            return
        if not safe_path(normalized, must_exist=True):
            errors.append(f"{normalized}: 심볼릭 링크 또는 안전하지 않은 설정 경로")
            return
        configs[normalized] = content
        try:
            scan = _scan_config(content)
        except _ConfigParseError as exc:
            errors.append(f"{normalized}: 설정 분석 실패({exc})")
            return
        scans[normalized] = scan
        for included in scan["includes"]:
            include_path = included
            if not posixpath.isabs(include_path):
                include_path = posixpath.join(posixpath.dirname(normalized), include_path)
            visit(include_path, required=True)

    for path in NAMED_CONFIGS:
        visit(path)
    return configs, scans, errors


def _inspect():
    configs, scans, errors = _load_configs()
    options_blocks = []
    allow_statements = []
    for path, scan in scans.items():
        for block in scan["options_blocks"]:
            options_blocks.append({"path": path, **block})
        for statement in scan["allow_statements"]:
            allow_statements.append({"path": path, **statement})

    if len(options_blocks) > 1:
        errors.append("유효 설정에 options 블록이 두 개 이상 존재")

    global_allow = [statement for statement in allow_statements if statement["is_global"]]
    issues = list(errors)
    for statement in allow_statements:
        if not statement["is_none_only"]:
            issues.append(
                f"{statement['path']}:{statement['line']}: deny 정책과 다른 allow-transfer 허용"
            )
    if configs and not global_allow:
        issues.append("전역 options 블록에 allow-transfer 미설정")

    return {
        "configs": configs,
        "scans": scans,
        "errors": errors,
        "issues": issues,
        "options_blocks": options_blocks,
        "allow_statements": allow_statements,
        "global_allow": global_allow,
    }


def _get_issues():
    inspection = _inspect()
    return inspection["issues"], list(inspection["configs"])


def _newline(content):
    return "\r\n" if "\r\n" in content else "\n"


def _options_indent(content, start):
    line_start = content.rfind("\n", 0, start) + 1
    prefix = content[line_start:start]
    return prefix if not prefix.strip() else ""


def _plan_changes(inspection=None):
    inspection = inspection or _inspect()
    if inspection["errors"]:
        return []

    edits = {path: [] for path in inspection["configs"]}
    for statement in inspection["allow_statements"]:
        if not statement["is_none_only"]:
            edits[statement["path"]].append(
                (statement["start"], statement["end"], "allow-transfer { none; };")
            )

    if not inspection["global_allow"]:
        if inspection["options_blocks"]:
            block = inspection["options_blocks"][0]
            content = inspection["configs"][block["path"]]
            newline = _newline(content)
            indent = _options_indent(content, block["start"]) + "\t"
            edits[block["path"]].append(
                (block["open_end"], block["open_end"],
                 f"{newline}{indent}allow-transfer {{ none; }};")
            )
        else:
            target = next(
                (path for path in OPTIONS_TARGETS if path in inspection["configs"]),
                next(iter(inspection["configs"]), None),
            )
            if target is not None:
                content = inspection["configs"][target]
                newline = _newline(content)
                separator = "" if not content or content.endswith(("\n", "\r")) else newline
                addition = (
                    f"{separator}options {{{newline}"
                    f"\tallow-transfer {{ none; }};{newline}"
                    f"}};{newline}"
                )
                edits[target].append((len(content), len(content), addition))

    changes = []
    for path, original in inspection["configs"].items():
        path_edits = edits[path]
        if not path_edits:
            continue
        updated = original
        last_start = len(original) + 1
        for start, end, replacement in sorted(path_edits, reverse=True):
            if end > last_start:
                return []
            updated = updated[:start] + replacement + updated[end:]
            last_start = start
        if updated != original:
            changes.append({"path": path, "original": original, "updated": updated})
    return changes

def _restore(changes):
    errors = []
    for change in changes:
        if not write_text(change["path"], change["original"]):
            errors.append(f"{change['path']}: 원본 복구 실패")
    return errors


def _validate_bind_config(path):
    if not command_exists("named-checkconf"):
        return "named-checkconf 명령을 찾지 못함"
    code, out, err = run_command(["named-checkconf", path], timeout=30)
    if code != 0:
        return f"named-checkconf 실패({err or out or code})"
    return None


def _active_bind_unit():
    for unit in ("bind9", "named"):
        if systemctl_is_active(unit):
            return unit
    return None


def _restart_bind(unit):
    if unit is None:
        return []
    code, out, err = run_command(["systemctl", "restart", unit], timeout=30)
    if code != 0:
        return [f"{unit} 재시작 실패({err or out or code})"]
    return []


def _validation_target(found):
    for path in ("/etc/bind/named.conf", "/etc/named.conf"):
        if path in found:
            return path
    return found[0]


def fix(dry_run=False):
    try:
        policy = policy_for(CODE)
        mode = require_choice(policy, "zone_transfer_mode", {"deny", "allow-secondary"})
        secondary_dns = require_string_list(policy, "secondary_dns")
    except PolicyError as exc:
        return result(CODE, TITLE, MANUAL, f"서버 정책 확인 필요: {exc}")
    if mode != "deny" or secondary_dns:
        return result(CODE, TITLE, MANUAL, "현재 자동 조치는 Secondary DNS가 없는 deny 정책만 지원함")

    inspection = _inspect()
    before = inspection["issues"]
    found = list(inspection["configs"])
    if inspection["errors"]:
        return result(CODE, TITLE, FAILED, "BIND 설정을 안전하게 분석하지 못해 변경하지 않음: " + summarize(inspection["errors"]))
    if not found:
        if command_exists("named"):
            return result(CODE, TITLE, FAILED, "named가 설치되어 있으나 BIND 설정 파일을 찾지 못함")
        return None
    if not before:
        return None

    changes = _plan_changes(inspection)
    if not changes:
        return result(CODE, TITLE, FAILED, "BIND 설정 변경 계획을 안전하게 생성하지 못함")
    if dry_run:
        return result(CODE, TITLE, FIXED, "dry-run: allow-transfer { none; }; 적용 예정 — " + summarize(before))
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return result(CODE, TITLE, FAILED, "root 권한 필요 — sudo로 실행하세요")

    errors, backups = [], []
    for change in changes:
        backup = backup_file(change["path"])
        if backup is None:
            errors.append(f"{change['path']}: 백업 실패로 변경하지 않음")
            break
        backups.append(backup)
        if not write_text(change["path"], change["updated"]):
            errors.append(f"{change['path']}: 쓰기 실패")
            break

    validation_target = _validation_target(found)
    if not errors:
        validation_error = _validate_bind_config(validation_target)
        if validation_error:
            errors.append(validation_error)

    unit = _active_bind_unit()
    if not errors:
        errors.extend(_restart_bind(unit))

    remaining = _inspect()
    if remaining["errors"]:
        errors.extend(remaining["errors"])
    if remaining["issues"]:
        errors.append("남은 취약 설정: " + summarize(remaining["issues"]))

    if errors:
        restore_errors = restore_backups(backups)
        restart_restore_errors = _restart_bind(unit) if backups else []
        details = ["오류: " + summarize(errors)]
        if restore_errors:
            details.append("원복 오류: " + summarize(restore_errors))
        elif backups:
            details.append("BIND 설정 원복 완료")
        if restart_restore_errors:
            details.append("원복 후 재시작 오류: " + summarize(restart_restore_errors))
        if backups:
            details.append("백업: " + summarize(backups))
        return result(CODE, TITLE, FAILED, " | ".join(details))

    return result(CODE, TITLE, FIXED, "Secondary DNS 없는 Open5GS 정책에 따라 Zone Transfer 전면 차단 완료" + (f" | 백업: {summarize(backups)}" if backups else ""))
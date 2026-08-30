"""서버별 조치 정책 로더.

기본 파일은 프로젝트 루트의 ``server_policy.json``이다. 다른 서버 정책은
``MEASURE_POLICY_FILE`` 환경 변수로 파일 경로를 지정해 교체할 수 있다.
정책이 명시적으로 확인되지 않았거나 형식이 잘못되면 위험한 자동 조치를
진행하지 않도록 ``PolicyError``를 발생시킨다.
"""

import json
import os
from pathlib import Path


DEFAULT_POLICY_PATH = Path(__file__).with_name("server_policy.json")


class PolicyError(ValueError):
    """정책 파일이 없거나 안전하게 해석할 수 없을 때 발생한다."""


def _policy_path():
    configured = os.environ.get("MEASURE_POLICY_FILE")
    return Path(configured).expanduser() if configured else DEFAULT_POLICY_PATH


def load_policy():
    path = _policy_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"정책 파일 없음: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"정책 파일 읽기 실패: {path} ({exc})") from exc

    if not isinstance(data, dict):
        raise PolicyError("정책 최상위 값은 객체여야 함")
    profile = data.get("profile")
    if not isinstance(profile, dict) or profile.get("confirmed") is not True:
        raise PolicyError("profile.confirmed=true인 승인된 정책이 필요함")
    return data


def policy_for(code):
    data = load_policy()
    key = str(code).lower().replace("-", "")
    section = data.get(key)
    if not isinstance(section, dict):
        raise PolicyError(f"{code} 정책 섹션 없음")
    return section


def require_bool(section, name):
    value = section.get(name)
    if type(value) is not bool:
        raise PolicyError(f"{name}은 true/false로 지정해야 함")
    return value


def require_string_list(section, name):
    value = section.get(name)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise PolicyError(f"{name}은 비어 있거나 문자열로 구성된 배열이어야 함")
    return [item.strip() for item in value]


def require_choice(section, name, choices):
    value = section.get(name)
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise PolicyError(f"{name}은 다음 중 하나여야 함: {allowed}")
    return value

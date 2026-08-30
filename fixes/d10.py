"""D-10 원격에서 DB 서버로의 접속 제한 조치

판단 기준(확인팀 5G_Check_Tool checks/d10.py 기준): mongod.conf의 net.bindIp에
"0.0.0.0"이나 "::"(광범위 바인딩)가 없으면 양호. 실제 리스닝 주소나 방화벽 상태는
확인팀 판정에 쓰이지 않으므로 이 조치도 같은 기준(설정 문자열)만 본다.

bindIp가 아예 없으면(기본값 = 모든 인터페이스 바인딩) 취약이지만, 이 환경에
필요한 접속 주체(Open5GS 컨테이너 등)를 알지 못한 채 bindIp를 임의로 채워 넣는 건
서비스 단절 위험이 있어 자동 조치하지 않고 MANUAL로 보류한다. 이미 광범위
바인딩(0.0.0.0/::)이 설정된 경우도 마찬가지로, 필요한 접속 범위를 모르는 채
bindIp를 임의로 좁히지 않는다.
"""

from fix_common import MANUAL, result, get_bind_ip

CODE = "D-10"
TITLE = "원격에서 DB 서버로의 접속 제한"
OPEN_BINDS = {"0.0.0.0", "::"}


def fix(dry_run=False):
    bind_ip = get_bind_ip()

    if bind_ip is None:
        return result(CODE, TITLE, MANUAL,
                      "mongod.conf에 bindIp가 설정되어 있지 않음(기본값 = 모든 인터페이스 바인딩) — "
                      "허용해야 할 접속 IP 범위를 알 수 없어 자동 조치 보류")

    addrs = [a.strip() for a in bind_ip.split(",")]
    open_addrs = [a for a in addrs if a in OPEN_BINDS]

    if not open_addrs:
        return None  # 이미 양호 (광범위 바인딩 없음)

    return result(CODE, TITLE, MANUAL,
                  f"bindIp: {bind_ip} — 광범위 바인딩({open_addrs}) 포함되어 취약하나, "
                  "허용해야 할 접속 IP 범위를 알 수 없어 bindIp를 임의로 좁히지 않음, 수동 확인 필요")

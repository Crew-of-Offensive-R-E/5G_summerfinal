# checks 패키지 — main.py 가 이 폴더의 uXX.py / dXX.py 를 자동 수집한다.
#
# 항목 파일 추가 방법: 이 폴더에 파일을 만들고 check() 만 작성하면 끝.
# 공통 함수는 프로젝트 루트 common.py 에서 바로 import 한다 ('checks.' 접두어 불필요).
#
#   # checks/u01.py
#   from common import GOOD, VULN, NA, result, read_text
#
#   CODE = "U-01"
#   TITLE = "root 계정 원격 접속 제한"
#
#   def check():
#       text = read_text("/etc/ssh/sshd_config")
#       if text is None:
#           return result(CODE, TITLE, NA, "sshd_config 없음")
#       ok = any(l.strip().lower().startswith("permitrootlogin no") for l in text.splitlines())
#       return result(CODE, TITLE, GOOD if ok else VULN, "PermitRootLogin 확인")
#
# MongoDB 인증이 필요한 항목은  def check(user=None, password=None):  시그니처를 쓴다.

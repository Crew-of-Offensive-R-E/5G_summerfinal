# 5G_summerfinal

**5G SA 코어 네트워크 취약점 점검 + 자동 조치 통합 도구**

KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)」 기준
Unix 서버 67개 + DBMS(MongoDB) 26개 = **총 93개 항목** 점검 및 자동 조치

---

## 파이프라인

```
1단계(점검)   checks/ 전체 실행 → 양호/취약/수동/N/A 판정
      ↓ 취약 항목만
2단계(조치)   fixes/ 해당 모듈 fix() 실행 → 조치완료/조치실패/수동제외
      ↓ 조치완료 항목만
3단계(재검증) checks/ 재실행 → 양호 전환 확인
```

---

## 프로젝트 구조

```
5G_summerfinal/
├── main.py            # 통합 파이프라인 (점검 → 조치 → 재검증)
├── check_common.py    # 확인팀 공통 유틸리티 (읽기 전용)
├── fix_common.py      # 조치팀 공통 유틸리티 (쓰기 포함)
├── checks/            # 확인팀 점검 모듈 (93개)
│   ├── u01.py ~ u67.py    # Unix 서버 점검
│   └── d01.py ~ d26.py    # DBMS MongoDB 점검
└── fixes/             # 조치팀 조치 모듈 (75개)
    ├── u01.py ~ u67.py    # Unix 서버 조치
    └── d01.py ~ d22.py    # DBMS MongoDB 조치 (자동 조치 가능 항목)
```

---

## 실행 방법

```bash
# 전체 파이프라인 (점검 → 조치 → 재검증)
sudo python3 main.py -u admin -p 'kmu2026!'

# 1단계 점검만 실행
sudo python3 main.py -u admin -p 'kmu2026!' --check

# 2단계 조치만 실행 (점검 건너뜀)
sudo python3 main.py -u admin -p 'kmu2026!' --fix

# 특정 항목만 실행
sudo python3 main.py -u admin -p 'kmu2026!' --only U-01 U-02 D-21

# 조치 시 실제 변경 없이 예정 동작만 출력
sudo python3 main.py -u admin -p 'kmu2026!' --dry-run

# 결과 파일 저장
sudo python3 main.py -u admin -p 'kmu2026!' --save results/report.txt
```

---

## 실행 옵션

| 옵션 | 설명 |
|------|------|
| `-u`, `--user` | MongoDB 인증 사용자 |
| `-p`, `--password` | MongoDB 인증 비밀번호 |
| `--check` | 1단계(점검)만 실행 |
| `--fix` | 2단계(조치)만 실행 |
| `--only` | 특정 항목만 실행 (예: `--only U-01 D-10`) |
| `--dry-run` | 조치 시 실제 변경 없이 예정 동작만 출력 |
| `--save` | 결과를 텍스트 파일로 저장 |

---

## 판정 상태

### 점검 (1단계)

| 상태 | 의미 |
|------|------|
| **양호** | KISA 가이드 기준 충족 |
| **취약** | 보안 설정 미흡, 조치 필요 |
| **수동** | 자동 판별 불가, 담당자 수동 확인 필요 |
| **N/A** | 해당 없음 (타 DBMS 전용 등) |

### 조치 (2단계)

| 상태 | 의미 |
|------|------|
| **조치완료** | 취약 → 양호로 자동 전환 성공 |
| **조치실패** | 조치 시도했으나 실패 |
| **수동제외** | 자동 조치 불가, 수동 대응 필요 |

---

## 테스트 환경

| 구성 | 상세 |
|------|------|
| VM | VMware / Ubuntu (172.16.97.136) |
| 5G 코어 | Open5GS v2.8.0 — Docker Compose (11개 NF + WebUI) |
| DBMS | MongoDB 8.0.28 (호스트 직접 실행) |
| 인증 | SCRAM-SHA-256, MONGODB-X509 |

---

## 원본 레포

- **확인팀**: [5G_Check_Tool](https://github.com/Crew-of-Offensive-R-E/5G_Check_Tool)
- **조치팀**: [5G_Measure_Tool](https://github.com/Crew-of-Offensive-R-E/5G_Measure_Tool)

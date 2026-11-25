# Verified Backup

[English](README.md) | **한국어** | [日本語](README.ja.md)

문서·코드·증거 자료 폴더를 SHA-256으로 검증 가능한 zip / tar.gz 백업으로 만들고,
기존 파일은 절대 덮어쓰지 않으면서 복원한 파일을 하나하나 다시 검증하는 도구입니다.
파이썬 표준 라이브러리만 사용하며 런타임 의존성이 없습니다.

## 해결하려는 문제

중요한 폴더를 그때그때 복사해 두는 방식은 조용히 실패하기 쉽습니다. 보관 중에 압축 파일이
손상되거나, 인증 정보 파일이 백업에 함께 들어가거나, "복원"이 더 최근 작업을 덮어쓰거나,
심볼릭 링크가 디스크의 엉뚱한 곳에 있는 파일을 끌어오기도 합니다. 그리고 이런 문제는 대개
백업이 정말 필요해진 순간에야 드러납니다.

Verified Backup은 모든 단계를 확인할 수 있게 만듭니다.

1. **scan** – 명시적인 포함/제외 규칙으로 원본 루트를 훑습니다.
2. **backup** – 아카이브 안에 매니페스트를 넣고, 모든 파일의 SHA-256과 크기를
   *실제로 아카이브에 기록된 바이트 기준으로* 남깁니다.
3. **verify** – 언제든 아카이브를 검증합니다(별도 체크섬 사이드카와 대조 가능).
4. **restore** – 새 폴더로 복원합니다. 기본은 dry-run이고, 파일마다 해시를 확인합니다.

## 보장하는 것

이 검사는 원본·출력·복원 폴더가 신뢰할 수 있고 안정적이라는 전제입니다. 공격자가 실행 중
파일시스템 경로를 바꾸는 상황까지 막지는 않습니다. 아래 한계를 함께 확인하세요.

- **내용 무결성.** 아카이브 안의 `BACKUP_MANIFEST.json`에 모든 페이로드 파일의 SHA-256과
  크기가 기록되며, 값은 아카이브에 실제로 쓴 바이트로 계산합니다. `verify`는 모든 멤버를
  다시 해시해 체크섬 불일치, 누락된 멤버, 예상하지 못한 멤버, 읽을 수 없는(손상된) 멤버를
  보고합니다.
- **아카이브 무결성.** `<archive>.checksums.json`에 아카이브 파일 자체의 SHA-256과 파일별
  해시를 저장하고, `verify --checksums`로 둘 다 확인합니다.
- **안전한 복원.**
  - 기본은 dry-run이며 `--execute` 없이는 아무것도 쓰지 않습니다.
  - 파일은 배타적 생성 모드로 만들기 때문에 기존 파일을 덮어쓰지 않습니다. 충돌이 하나라도
    있으면 아무것도 쓰기 전에 복원을 중단합니다.
  - 기록된 원본 경로나 루트 지문으로 원본 루트 위의 직접 복원을 거부합니다.
  - 복원한 파일마다 해시를 매니페스트와 비교하고, 마지막에 복원된 트리 전체를 다시 검증합니다.
  - 중간 오류나 최종 검증 실패 시 부분 쓰기 파일을 포함해 이번 실행에서 만든 파일·폴더의
    롤백을 시도합니다. 기존 대상 파일은 삭제 대상으로 삼지 않습니다. 정리 권한이 필요하며,
    프로세스 강제 종료나 정전 뒤의 정리까지 보장하지는 않습니다.
- **경로 안전성.** 아카이브 멤버는 `payload/` 아래에 있어야 하고, 절대 경로와 `..`는
  거부합니다. 파일이 아닌 tar 멤버(링크, 장치 등)도 거부하며, 규칙의 대상 경로가 원본 루트
  밖을 가리키는 것도 막습니다.
- **링크를 몰래 따라가지 않습니다.** 심볼릭 링크와 Windows 정션은 경로를 resolve하기 전에,
  해석되지 않은 경로의 구성 요소를 하나씩 검사해 판별합니다. 기본값(`skip_symlinks: true`)에서는
  링크를 거친 파일을 건너뛰고 `symlink` 사유별 개수로 남깁니다. `skip_symlinks: false`이면
  링크의 실제 위치가 원본 루트 안일 때만 따라가고, 루트 밖이면 `outside_root` 사유로 제외합니다.
- **비밀 정보로 보이는 파일 이름은 제외합니다**(`.env`, `*token*`, `*.pem`, `id_rsa*` 등).
  해시나 압축보다 먼저 걸러지며, 기본 매니페스트에는 사유별 개수만 남습니다.
  자세한 경로는 아래의 비공개 메타데이터 옵션을 명시해야 기록됩니다.

## 설계

```
rules.json ──► scan_source ──► build_backup_manifest ──► write_archive ──► write_sidecar_manifests
                 (분류, 해시)                               (zip | tar.gz)      (.manifest.json, .checksums.json)

archive ──► verify_archive            archive ──► restore_archive (dry-run | execute) ──► verify_restored_tree
```

아카이브 구조:

```
BACKUP_MANIFEST.json        파일 해시/크기, 루트 지문, 제외 사유별 개수
payload/<relative/path>     원본 루트 기준 상대 경로의 파일 내용
```

아카이브 옆에 생기는 사이드카:

- `<archive>.manifest.json` – 내장 매니페스트 사본(같은 비공개 설정 적용)
- `<archive>.checksums.json` – 아카이브 SHA-256과 파일별 SHA-256/크기

| 모듈 | 역할 |
| --- | --- |
| `config.py` | 규칙 파일 로드·검증, 원본 루트 확인 |
| `scanner.py` | 대상 확장, 제외 분류(링크 우선), 파일 해시, 매니페스트 생성 |
| `archive.py` | zip / tar.gz 아카이브와 사이드카 작성 |
| `verify.py` | 내장 매니페스트 읽기, 페이로드 재해시, 사이드카·멤버 경로 확인 |
| `restore.py` | dry-run 계획, 롤백을 갖춘 무덮어쓰기 복원, 임시 폴더 복원 |
| `paths.py` | 상대 경로 정규화, 포함 관계 확인, 심볼릭 링크/정션 판별 |
| `cli.py` | `verified-backup` 명령 |

### 규칙

규칙은 JSON입니다. 대상 경로는 원본 루트 기준 상대 경로이며, 패턴은 `/`를 쓰고 대소문자를
구분하지 않습니다. `**/`는 폴더가 하나도 없는 경우에도 맞으므로, `**/.git/**`는 원본 루트
바로 아래를 포함해 어느 깊이에 있는 `.git` 폴더든 제외합니다.

```json
{
  "schema_version": "verified-backup-rules/v1",
  "targets": [
    {"name": "documents", "path": "documents", "include": ["**/*"], "exclude": ["**/~$*"]},
    {"name": "code", "path": "code", "include": ["**/*.py", "**/*.toml", "**/*.md"]},
    {"name": "evidence", "path": "evidence", "include": ["**/*"]}
  ],
  "exclude": {
    "skip_symlinks": true,
    "path_patterns": ["**/.git/**", "**/__pycache__/**", "**/*.tmp"],
    "secret_name_patterns": [".env", "*token*", "*.pem"]
  }
}
```

매니페스트에 기록되는 제외 사유(검사 순서대로): `symlink`, `outside_root`, `secret_name`,
`global_exclude`, `target_exclude`.

패키지에 들어 있는 기본 규칙(`verified-backup rules`로 출력)은 VCS 메타데이터, 캐시, 가상환경,
임시·잠금 파일, 링크, 비밀 정보로 보이는 이름을 뺀 원본 루트 아래의 **모든 파일**을 백업합니다.
여러 대상을 쓰는 예시는 [`examples/rules.example.json`](examples/rules.example.json)을 보세요.

## 빠른 시작

```bash
pip install .            # 개발용: pip install -e ".[test]"

# 무엇이 백업될지 미리 보기
verified-backup scan --root ./my-folder --output manifest.json

# 아카이브(zip 또는 tar)와 사이드카 만들기
verified-backup backup --root ./my-folder --output-dir backups --format zip --name my-folder-2026-01-01

# 아카이브와 사이드카 검증
verified-backup verify backups/my-folder-2026-01-01.zip --checksums backups/my-folder-2026-01-01.zip.checksums.json

# 복원: 먼저 dry-run, 그다음 새 폴더로 실제 복원
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check --execute --verify-first

# 새 임시 폴더로 복원하고 검증(기본적으로 아카이브를 먼저 검증)
verified-backup restore-temp backups/my-folder-2026-01-01.zip --temp-root ./restore-tmp

# 사용자 규칙 사용
verified-backup backup --root ./my-folder --config my_rules.json --output-dir backups
```

`--root`는 `scan`과 `backup`에만 필수이고, 이 두 명령에 암묵적인 기본 원본은 없습니다.
`verify`, `restore`, `restore-temp`, `rules`는 이 옵션을 받지 않습니다.
`python -m verified_backup`으로도 실행할 수 있습니다. 작업 결과·오류는 JSON이며
`--help`와 인자 파서 오류는 텍스트입니다. 종료 코드는 `0` 성공, `1`은
`"ok": false` 결과(검증 실패, dry-run 충돌, 스캔 대상 누락), `2`는 오류
(잘못된 규칙·루트·아카이브, 거부된 백업·복원)입니다.

### 안전 기본값과 공유

- 설정한 대상 경로는 모두 필수입니다. 누락 시 `scan`은 누락 개수를 보고하고 `1`로,
  `backup`은 아카이브를 만들기 전에 `2`로 끝납니다. 선택 대상 플래그는 없습니다.
  존재하지만 비어 있는 폴더나 일치 파일이 없는 include 패턴은 경로 누락이 아닙니다.
  빈 백업을 허용하지 않으려면 `summary.file_count`도 확인하세요.
- `--output-dir`는 반드시 `--root` **밖**에 두세요. CLI는 출력 트리를 자동 제외하는
  대신 원본과 같거나 원본 안인 출력을 거부합니다. 원본 안에서 실행할 때는
  `verified-backup backup --root . --output-dir ../backups`를 쓰세요. 기본 `backups`는
  원본이 아닌 현재 작업 폴더 기준입니다. `--name`은 경로가 아닌 파일명 줄기 하나입니다.
  경로 구분자, ADS 콜론, Windows 예약 이름은 거부합니다.
- 아카이브는 고유한 이웃 임시 파일을 배타 생성한 뒤 기존 경로를 바꾸지 않는 하드 링크로
  게시합니다. 하드 링크를 지원하지 않는 파일시스템에서는 실패 처리합니다. 기존 아카이브,
  사이드카, `scan --output` 파일은 바꾸지 않으므로 새 이름을 쓰세요. 사이드카 쓰기 실패 시
  먼저 완성된 아카이브는 남을 수 있습니다. 세 파일 전체가 하나의 충돌·정전 원자적 트랜잭션은
  아닙니다. 종료 코드를 확인하고 남은 파일을 검사·검증하세요.
- 기본 매니페스트는 원본 절대경로, 규칙 스냅샷, 제외·누락 이름, 대상 라벨을 생략합니다.
  `excluded_counts`, 요약 개수, 포함된 상대 이름·해시·크기·시각과 `source_root_sha256`은
  남깁니다. 루트 지문은 비교용 식별자이지 **익명화가 아닙니다**. 추측한 경로와 대조할 수
  있고 포함 이름·본문에도 사생활이 남을 수 있습니다. 아카이브는 암호화하지 않습니다.
- 자세한 **로컬 전용** 스캔은 명시적으로 켜세요.

  ```bash
  verified-backup scan --root ./my-folder --output local-private.json --include-private-metadata
  ```

  `backup --include-private-metadata`는 아카이브 내부와 매니페스트 사이드카에도 상세 정보를
  넣으므로 공유하지 마세요. Python에서는
  `build_backup_manifest(scan, rules, include_private_metadata=True)`를 씁니다.
- 기본 규칙은 기존 패턴 외에도 `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, `auth.json`,
  `*.ppk`, `*.jks`, `*.keystore`, `wallet.dat`, `.git-credentials`와 `.ssh`, `.gnupg`,
  `.aws`, `.kube`, `.docker` 트리를 모든 깊이에서 제외합니다. 사용자 규칙 파일은 기본값과
  **병합하지 않고 교체**합니다. 로컬 비공개 스캔으로 확인하세요. 평범한 `settings.json`의
  인증정보, 브라우저 `Login Data`, 이름을 바꾼 키는 여전히 포함될 수 있습니다.
  본문 비밀 검사는 하지 않습니다.
- 읽을 때 잘못된 매니페스트 필드, 중복 멤버·경로(대소문자만 다른 경우 포함), 누락·추가
  페이로드, 경로 탈출, 역슬래시, ADS `:`, Windows 장치 이름, 끝의 점·공백, 파일/폴더
  충돌을 거부합니다. 크기와 SHA-256이 모두 맞아야 합니다. 이식성 때문에 POSIX에서는
  유효한 일부 이름도 거부합니다.
  백업 생성도 아카이브를 최종 경로에 만들기 전에 같은 규칙으로 최종 매니페스트를 검사합니다.
  지원하지 않는 이름이나 충돌이 있으면 복원할 수 없는 백업을 만드는 대신 오류로 중단합니다.

## Python API

```python
from pathlib import Path

from verified_backup.archive import write_archive, write_sidecar_manifests
from verified_backup.config import load_rules, resolve_source_root
from verified_backup.restore import restore_archive, restore_to_temp
from verified_backup.scanner import build_backup_manifest, scan_source
from verified_backup.verify import verify_archive

rules = load_rules()                                  # 또는 load_rules("my_rules.json")
root = resolve_source_root("my-folder")
scan = scan_source(root, rules)
if scan.missing_targets:
    raise RuntimeError("Missing configured targets")
manifest = build_backup_manifest(scan, rules, archive_format="zip")

archive = Path("backups/my-folder.zip")
final_manifest = write_archive(archive_path=archive, archive_format="zip",
                               manifest=manifest, files=scan.files)
_, checksums = write_sidecar_manifests(archive_path=archive, manifest=final_manifest)

assert verify_archive(archive, checksums)["ok"]
plan = restore_archive(archive_path=archive, dest=Path("restore-check"))               # dry-run
done = restore_archive(archive_path=archive, dest=Path("restore-check"), execute=True,
                       verify_first=True)
```

예외: `ConfigError`(규칙/원본 루트), `ArchiveError`(지원하지 않거나 손상되었거나 앞뒤가 맞지 않는
아카이브), `RestoreSafetyError`(충돌, 원본 루트 위 복원, 사전 검증 실패).
저수준 writer가 원본·출력 배치를 대신 정하지는 않습니다. `archive`를 `root` 밖에 두고
실행마다 새 경로를 쓰세요.

## 예제

[`examples/end_to_end_demo.py`](examples/end_to_end_demo.py)는 임시 폴더에 작은 합성 데이터
트리를 만들고 CLI로 백업, 검증, dry-run, 복원, 충돌 거부, 변조 탐지까지 차례로 보여 줍니다.

```bash
python examples/end_to_end_demo.py
```

## 테스트 실행

```bash
pip install -e ".[test]"
pytest -q
```

심볼릭 링크를 만들어야 하는 테스트는 OS가 허용하지 않으면(예: 개발자 모드가 꺼진 Windows)
건너뜁니다. Windows 정션 테스트는 별도 권한 없이 실행됩니다.

## 한계와 비목표

- **실행 중인 SQLite 데이터베이스는 스냅샷이 아니라 바이트 그대로 복사됩니다.** 백업하는 동안
  DB에 쓰기가 일어나면 아카이브에 담긴 `.db` / `-wal` / `-shm` 파일끼리 일관성이 깨질 수
  있습니다(WAL 모드에서는 최근 커밋이 `-wal` 파일에 있습니다). 해시는 그 깨진 사본을 그대로
  기술할 뿐입니다. 쓰는 프로세스를 먼저 멈추거나, SQLite 백업 API로 만든 스냅샷을 백업하세요.
  예: `sqlite3.connect("live.db").backup(sqlite3.connect("snapshot.db"))` 또는
  `sqlite3 live.db ".backup snapshot.db"`.
- **파일시스템 스냅샷이 아닙니다.** 파일을 하나씩 읽습니다. 매니페스트에는 실제로 아카이브된
  바이트가 기록되지만, 읽는 *도중에* 바뀐 파일은 중간이 섞인 상태로 담길 수 있습니다.
- **비밀 정보 탐지는 파일 이름 기준입니다.** 파일 내용은 검사하지 않습니다. 기본 패턴은 일부러
  넓게 잡았기 때문에 과하게 제외될 수 있습니다(예: `tokenizer.py`가 `*token*`에 걸림).
  `excluded_counts`를 확인하거나 로컬 비공개 스캔을 켜서 자세한 `excluded` 목록을 보고 규칙을 조정하세요.
- **무결성이지 진본성은 아닙니다.** 체크섬은 우발적인 손상을 잡아내지만, 아카이브와 사이드카를
  둘 다 고쳐 쓸 수 있는 사람까지 막지는 못합니다. 그게 중요하다면 사이드카나 그 해시를 따로
  보관하세요. 아카이브는 암호화하지 않습니다.
- **내용만 복원합니다.** 복원된 파일의 시각은 새로 정해지고, 권한, 소유자, ACL, 확장 속성,
  빈 디렉터리는 보존하지 않습니다.
- **메모리 사용.** tar 페이로드와 복원할 멤버는 메모리에 통째로 읽으므로, 아주 큰 단일 파일에는
  그만큼의 RAM이 필요합니다. 멤버 수·압축 해제 크기 제한이 없으므로 비신뢰 아카이브용
  샌드박스로 쓰지 마세요.
- **파일시스템 경쟁과 내구성.** 경로 검사와 파일 열기는 별개입니다. 배타 생성과 무덮어쓰기
  게시도 악의적인 동시 상위 경로·심볼릭 링크/정션·임시 파일·하드 링크/8.3 별칭 교체까지
  막지는 못합니다. 신뢰하는 사용자만 쓸 수 있는 폴더에서 다른 쓰기를 멈추고 실행하세요.
  루트 지문은 파일시스템 동일성 증명이 아닙니다. 디렉터리 fsync, 복구 저널, 검증된 정전
  보장은 없습니다. 정리 자체가 실패하면 롤백은 최선의 시도에 그치므로 대상을 직접 확인하세요.
- **정션 순회.** 파이썬 `glob`은 Windows 정션 안으로 들어갑니다. 그 안에서 찾은 파일은
  제외되지만 디렉터리 순회 자체는 일어나므로, 정션이 순환하면 스캔이 느려집니다.
- 백업 스케줄러가 아닙니다. 증분/중복 제거 백업, 보존 정책, 원격 저장소는 다루지 않습니다.

## 출처

원래 개인 AI 비서 프로젝트인 willind의 일부로 개발되어, 비서의 문서·데이터 저장소·로그를
백업하는 데 쓰였습니다. 이 저장소는 그 부분을 독립적으로 떼어 낸 것으로, 프로젝트 전용 규칙과
경로를 없애고 원본 루트를 항상 명시적으로 받도록 바꿨습니다.

## 라이선스

Apache License 2.0. [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.

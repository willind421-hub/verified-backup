# Verified Backup

[English](README.md) | [한국어](README.ko.md) | **日本語**

文書・コード・エビデンスのフォルダを、SHA-256 で検証できる zip / tar.gz バックアップにまとめ、
既存のファイルを決して上書きせずに、書き出したファイルを一つずつ再検証しながら復元するツールです。
Python 標準ライブラリのみで動作し、実行時の依存関係はありません。

## 解決する問題

大事なフォルダをその場しのぎでコピーするやり方は、気づかないうちに失敗しがちです。保管中に
アーカイブが壊れる、認証情報のファイルが一緒に紛れ込む、「復元」が新しい作業を上書きしてしまう、
シンボリックリンクがディスク上の別の場所のファイルを引き込む――。こうした問題は、たいてい
バックアップが本当に必要になったときに初めて発覚します。

Verified Backup は、すべての段階を確認可能にします。

1. **scan** – 明示的な包含/除外ルールでソースルートを走査します。
2. **backup** – アーカイブ内にマニフェストを埋め込み、すべてのファイルの SHA-256 とサイズを
   *実際にアーカイブへ書き込んだバイト列に基づいて* 記録します。
3. **verify** – いつでもアーカイブを検証できます（別ファイルのチェックサムとも照合可能）。
4. **restore** – 新しいフォルダへ復元します。既定は dry-run で、ファイルごとにハッシュを確認します。

## 保証すること

- **内容の完全性。** アーカイブ内の `BACKUP_MANIFEST.json` に、すべてのペイロードファイルの
  SHA-256 とサイズを記録します。値はアーカイブに実際に書き込んだバイト列から計算します。
  `verify` は全メンバーを再ハッシュし、チェックサム不一致、欠落、想定外のメンバー、
  読み取れない（破損した）メンバーを報告します。
- **アーカイブの完全性。** `<archive>.checksums.json` にアーカイブファイル自体の SHA-256 と
  ファイルごとのハッシュを保存し、`verify --checksums` で両方を確認します。
- **安全な復元。**
  - 既定は dry-run で、`--execute` を付けない限り何も書き込みません。
  - ファイルは排他的作成モードで作るため、既存ファイルを上書きすることはありません。衝突が一つでも
    あれば、何かを書き込む前に復元を中止します。
  - マニフェストに記録されたソースルートへ直接復元することは拒否します。
  - 復元したファイルごとにハッシュをマニフェストと照合し、最後に復元ツリー全体を再検証します。
  - 復元が途中で失敗した場合（破損したアーカイブ、チェックサム不一致、I/O エラー）、その実行で
    作成したファイルとディレクトリをすべて削除します。復元先に元からあったファイルはそのまま残ります。
- **パスの安全性。** アーカイブのメンバーは `payload/` 配下でなければならず、絶対パスと `..` は
  拒否します。ファイル以外の tar メンバー（リンク、デバイスなど）も拒否し、ルールの対象パスが
  ソースルートの外を指すことも防ぎます。
- **リンクを黙って辿りません。** シンボリックリンクと Windows のジャンクションは、パスを resolve
  する前に、未解決のパスの構成要素を一つずつ調べて判定します。既定（`skip_symlinks: true`）では
  リンクを経由するファイルをスキップし、理由 `symlink` としてマニフェストに記録します。
  `skip_symlinks: false` の場合は、リンクの実体がソースルート内にあるときだけ辿り、ルート外なら
  理由 `outside_root` で除外します。
- **秘密情報らしいファイル名は除外します**（`.env`、`*token*`、`*.pem`、`id_rsa*` など）。
  ハッシュ計算やアーカイブ化より前に除外し、除外したファイルはすべて理由とともにマニフェストへ
  記録します。

## 設計

```
rules.json ──► scan_source ──► build_backup_manifest ──► write_archive ──► write_sidecar_manifests
                 (分類, ハッシュ)                           (zip | tar.gz)      (.manifest.json, .checksums.json)

archive ──► verify_archive            archive ──► restore_archive (dry-run | execute) ──► verify_restored_tree
```

アーカイブの構成:

```
BACKUP_MANIFEST.json        完全なマニフェスト: ソースルート、ルールのスナップショット、ファイル、除外一覧
payload/<relative/path>     ソースルートからの相対パスで格納したファイル内容
```

アーカイブの隣に作成されるサイドカー:

- `<archive>.manifest.json` – 完全なマニフェストのコピー
- `<archive>.checksums.json` – アーカイブの SHA-256 とファイルごとの SHA-256/サイズ

| モジュール | 役割 |
| --- | --- |
| `config.py` | ルールファイルの読み込みと検証、ソースルートの確認 |
| `scanner.py` | 対象の展開、除外の分類（リンクを最優先）、ハッシュ計算、マニフェスト作成 |
| `archive.py` | zip / tar.gz アーカイブとサイドカーの書き込み |
| `verify.py` | 埋め込みマニフェストの読み込み、ペイロードの再ハッシュ、サイドカーとメンバーパスの確認 |
| `restore.py` | dry-run の計画、ロールバック付きの上書きしない復元、一時フォルダへの復元 |
| `paths.py` | 相対パスの正規化、包含関係の確認、シンボリックリンク/ジャンクションの判定 |
| `cli.py` | `verified-backup` コマンド |

### ルール

ルールは JSON です。対象パスはソースルートからの相対パスで、パターンは `/` 区切り、
大文字と小文字を区別せずに照合します。`**/` はディレクトリが一つもない場合にも一致するため、
`**/.git/**` はソースルート直下を含め、どの深さにある `.git` フォルダーも除外します。

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

マニフェストに記録される除外理由（判定順）: `symlink`、`outside_root`、`secret_name`、
`global_exclude`、`target_exclude`。

パッケージ同梱の既定ルール（`verified-backup rules` で表示）は、VCS メタデータ、キャッシュ、仮想環境、
一時ファイル・ロックファイル、リンク、秘密情報らしい名前を除いた、ソースルート配下の**すべての
ファイル**をバックアップします。複数対象の例は
[`examples/rules.example.json`](examples/rules.example.json) を参照してください。

## クイックスタート

```bash
pip install .            # 開発時: pip install -e ".[test]"

# バックアップ対象のプレビュー
verified-backup scan --root ./my-folder --output manifest.json

# アーカイブ（zip または tar）とサイドカーを作成
verified-backup backup --root ./my-folder --output-dir backups --format zip --name my-folder-2026-01-01

# アーカイブとサイドカーを検証
verified-backup verify backups/my-folder-2026-01-01.zip --checksums backups/my-folder-2026-01-01.zip.checksums.json

# 復元: まず dry-run、その後で新しいフォルダへ実行
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check --execute --verify-first

# 新しい一時フォルダへ復元して検証（既定でアーカイブを先に検証）
verified-backup restore-temp backups/my-folder-2026-01-01.zip --temp-root ./restore-tmp

# 独自ルールを使う
verified-backup backup --root ./my-folder --config my_rules.json
```

`--root` は常に必須で、暗黙の既定ソースはありません。`python -m verified_backup` でも実行できます。
すべてのコマンドは JSON を出力します。終了コード: `0` 成功、`1` 結果が `"ok": false`
（検証失敗、dry-run での衝突）、`2` エラー（不正なルール、存在しないルート、破損したアーカイブ、
拒否された復元）。

## Python API

```python
from pathlib import Path

from verified_backup.archive import write_archive, write_sidecar_manifests
from verified_backup.config import load_rules, resolve_source_root
from verified_backup.restore import restore_archive, restore_to_temp
from verified_backup.scanner import build_backup_manifest, scan_source
from verified_backup.verify import verify_archive

rules = load_rules()                                  # または load_rules("my_rules.json")
root = resolve_source_root("my-folder")
scan = scan_source(root, rules)
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

例外: `ConfigError`（ルール/ソースルート）、`ArchiveError`（未対応・破損・不整合のアーカイブ）、
`RestoreSafetyError`（衝突、ソースルートへの復元、事前検証の失敗）。

## サンプル

[`examples/end_to_end_demo.py`](examples/end_to_end_demo.py) は一時ディレクトリに小さな合成データの
ツリーを作り、CLI でバックアップ、検証、dry-run、復元、衝突時の拒否、改ざん検出までを順に実行します。

```bash
python examples/end_to_end_demo.py
```

## テストの実行

```bash
pip install -e ".[test]"
pytest -q
```

シンボリックリンクの作成が必要なテストは、OS が許可しない環境（例: 開発者モードが無効な Windows）
ではスキップされます。Windows のジャンクションのテストは追加の権限なしで実行されます。

## 制限事項と対象外

- **稼働中の SQLite データベースはスナップショットではなく、バイト列のままコピーされます。**
  バックアップ中に書き込みがあると、アーカイブ内の `.db` / `-wal` / `-shm` ファイル同士の整合性が
  崩れることがあります（WAL モードでは最近のコミットが `-wal` ファイルにあります）。ハッシュは
  その不整合なコピーを忠実に記述するだけです。書き込み側を先に止めるか、SQLite のバックアップ API で
  作ったスナップショットをバックアップしてください。例:
  `sqlite3.connect("live.db").backup(sqlite3.connect("snapshot.db"))` または
  `sqlite3 live.db ".backup snapshot.db"`。
- **ファイルシステムのスナップショットではありません。** ファイルは一つずつ読み込みます。
  マニフェストには実際にアーカイブしたバイト列が記録されますが、読み込みの*最中に*変更された
  ファイルは中途半端な状態で取り込まれることがあります。
- **秘密情報の検出はファイル名のみに基づきます。** ファイルの内容は検査しません。既定のパターンは
  意図的に広めに取っているため、除外しすぎることがあります（例: `tokenizer.py` が `*token*` に一致）。
  マニフェストの `excluded` 一覧を確認し、ルールを調整してください。
- **完全性であって真正性ではありません。** チェックサムは偶発的な破損を検出しますが、アーカイブと
  サイドカーの両方を書き換えられる相手は防げません。必要であればサイドカーやそのハッシュを別の場所に
  保管してください。アーカイブは暗号化されません。
- **復元されるのは内容のみです。** 復元したファイルのタイムスタンプは新しくなり、パーミッション、
  所有者、ACL、拡張属性、空のディレクトリは保持されません。
- **メモリ使用量。** tar のペイロードと復元対象のメンバーは丸ごとメモリに読み込むため、非常に大きな
  単一ファイルには相応の RAM が必要です。
- **ジャンクションの走査。** Python の `glob` は Windows のジャンクションの中まで降りていきます。
  見つかったファイルは除外されますが、ディレクトリの列挙自体は行われるため、ジャンクションが
  循環しているとスキャンが遅くなります。
- バックアップスケジューラではありません。増分・重複排除バックアップ、保持ポリシー、リモート保存は
  扱いません。

## 由来

もともとは個人向け AI アシスタントプロジェクト willind の一部として開発され、アシスタントの文書、
データストア、ログのバックアップに使われていました。このリポジトリはその部分を独立させたもので、
プロジェクト固有のルールとパスを取り除き、ソースルートを常に明示的に指定する形に変更しています。

## ライセンス

Apache License 2.0。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。

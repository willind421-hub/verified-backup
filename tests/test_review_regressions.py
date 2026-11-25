"""Synthetic regressions for the reviewed failure paths."""
from __future__ import annotations

import io
import json
import hashlib
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from verified_backup.archive import ArchiveError, write_archive, write_sidecar_manifests
from verified_backup.config import load_rules
from verified_backup.scanner import scan_source, build_backup_manifest


def source(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'one.txt').write_bytes(b'one')
    rules = load_rules()
    scan = scan_source(root.resolve(), rules)
    return root, scan, build_backup_manifest(scan, rules)


@pytest.mark.parametrize('fmt,ext', [('zip', '.zip'), ('tar', '.tar.gz')])
def test_archive_publication_never_clobbers_and_cleans_failed_build(tmp_path, monkeypatch, fmt, ext):
    import verified_backup.archive as module
    root, scan, manifest = source(tmp_path)
    archive = tmp_path / ('backup' + ext)
    old_tmp = archive.with_name(archive.name + '.tmp')
    old_tmp.write_bytes(b'foreign temporary file')
    write_archive(archive_path=archive, archive_format=fmt, manifest=manifest, files=scan.files)
    assert old_tmp.read_bytes() == b'foreign temporary file'
    before = archive.read_bytes()
    with pytest.raises((ArchiveError, FileExistsError)):
        write_archive(archive_path=archive, archive_format=fmt, manifest=manifest, files=scan.files)
    assert archive.read_bytes() == before
    failed = tmp_path / ('failed' + ext)
    def fail(*args, **kwargs):
        raise OSError('synthetic write failure')
    monkeypatch.setattr(module, '_write_zip_payload' if fmt == 'zip' else '_write_tar_payload', fail)
    with pytest.raises(OSError, match='synthetic'):
        write_archive(archive_path=failed, archive_format=fmt, manifest=manifest, files=scan.files)
    assert not failed.exists()
    assert {p.name for p in tmp_path.iterdir()} == {'source', archive.name, old_tmp.name}


def test_concurrent_archive_publication_has_one_winner(tmp_path):
    _, scan, manifest = source(tmp_path)
    archive = tmp_path / 'race.zip'
    def attempt(_):
        try:
            write_archive(archive_path=archive, archive_format='zip', manifest=manifest, files=scan.files)
            return True
        except (ArchiveError, FileExistsError):
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        winners = list(pool.map(attempt, range(4)))
    assert winners.count(True) == 1
    with zipfile.ZipFile(archive) as zf:
        assert zf.read('payload/one.txt') == b'one'


def test_sidecar_race_does_not_clobber_or_leave_partial_pair(tmp_path, monkeypatch):
    _, scan, manifest = source(tmp_path)
    archive = tmp_path / 'backup.zip'
    manifest = write_archive(archive_path=archive, archive_format='zip', manifest=manifest, files=scan.files)
    checksum = archive.with_name(archive.name + '.checksums.json')
    original = Path.open
    def race(path, mode='r', *args, **kwargs):
        if path == checksum and mode in ('w', 'x'):
            with original(path, 'xb') as f:
                f.write(b'foreign winner')
        return original(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', race)
    with pytest.raises((ArchiveError, FileExistsError)):
        write_sidecar_manifests(archive_path=archive, manifest=manifest)
    assert checksum.read_bytes() == b'foreign winner'
    assert not archive.with_name(archive.name + '.manifest.json').exists()


def synthetic_archive(tmp_path, entries, payloads, fmt='zip'):
    manifest = {'schema_version': 'verified-backup-manifest/v1', 'files': entries}
    archive = tmp_path / ('crafted.zip' if fmt == 'zip' else 'crafted.tar.gz')
    members = [('BACKUP_MANIFEST.json', json.dumps(manifest).encode()), *payloads]
    if fmt == 'zip':
        with zipfile.ZipFile(archive, 'w') as zf:
            for name, data in members:
                zf.writestr(name, data)
    else:
        with tarfile.open(archive, 'w:gz') as tf:
            for name, data in members:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tf.addfile(member, io.BytesIO(data))
    return archive


def entry(path='nested/one.txt', data=b'one', size=None):
    return {'path': path, 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data) if size is None else size}


@pytest.mark.parametrize('failure', ['missing', 'size', 'final-read', 'file-reread'])
def test_any_restore_failure_rolls_back_owned_files_and_dirs(tmp_path, monkeypatch, failure):
    import verified_backup.restore as module
    entries = [entry(size=100 if failure == 'size' else None)]
    if failure == 'missing':
        entries.append(entry('nested/two.txt'))
    archive = synthetic_archive(tmp_path, entries, [('payload/nested/one.txt', b'one')])
    dest = tmp_path / 'dest'
    dest.mkdir()
    (dest / 'keep.txt').write_bytes(b'untouched')
    if failure == 'final-read':
        def fail(*args):
            raise OSError('synthetic final verification read failure')
        monkeypatch.setattr(module, 'verify_restored_tree', fail)
    if failure == 'file-reread':
        original = Path.open
        def fail(path, mode='r', *args, **kwargs):
            if path == dest / 'nested/one.txt' and mode == 'rb':
                raise OSError('synthetic reread failure')
            return original(path, mode, *args, **kwargs)
        monkeypatch.setattr(Path, 'open', fail)
    try:
        result = module.restore_archive(archive_path=archive, dest=dest, execute=True)
        assert result['ok'] is False
    except (OSError, ArchiveError):
        pass
    assert list(dest.iterdir()) == [dest / 'keep.txt']
    assert (dest / 'keep.txt').read_bytes() == b'untouched'


def test_write_helper_removes_file_on_postwrite_read_error(tmp_path, monkeypatch):
    from verified_backup.restore import write_new_file_with_hash
    out = tmp_path / 'new.txt'
    original = Path.open
    def fail(path, mode='r', *args, **kwargs):
        if path == out and mode == 'rb':
            raise OSError('synthetic postwrite read failure')
        return original(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fail)
    with pytest.raises(OSError):
        write_new_file_with_hash(io.BytesIO(b'one'), out)
    assert not out.exists()


def test_backup_refuses_output_under_source(tmp_path, capsys):
    from verified_backup.cli import main
    root, _, _ = source(tmp_path)
    out = root / 'backups'
    assert main(['backup', '--root', str(root), '--output-dir', str(out)]) == 2
    assert not out.exists()
    assert 'outside' in capsys.readouterr().err.lower()


@pytest.mark.parametrize('name', ['../source/escaped', 'nested/name', r'nested\name',
                                  'C:drive', 'NUL', 'bad.', 'bad '])
def test_backup_name_cannot_escape_output_directory(tmp_path, capsys, name):
    from verified_backup.cli import main
    root, _, _ = source(tmp_path)
    out = tmp_path / 'backups'
    assert main(['backup', '--root', str(root), '--output-dir', str(out),
                 '--name', name]) == 2
    assert json.loads(capsys.readouterr().err)['ok'] is False
    assert list(root.iterdir()) == [root / 'one.txt']
    assert not out.exists() or not list(out.iterdir())


@pytest.mark.parametrize('command', ['scan', 'backup'])
def test_missing_configured_target_is_failure(tmp_path, capsys, command):
    from verified_backup.cli import main
    root, _, _ = source(tmp_path)
    rules = load_rules()
    rules['targets'].append({'name': 'required', 'path': 'missing', 'include': ['**/*']})
    config = tmp_path / 'rules.json'
    config.write_text(json.dumps(rules), encoding='utf-8')
    out = tmp_path / 'backups'
    args = [command, '--root', str(root), '--config', str(config)]
    if command == 'backup':
        args += ['--output-dir', str(out)]
    assert main(args) != 0
    captured = capsys.readouterr()
    assert json.loads(captured.err or captured.out)['ok'] is False
    assert not out.exists()


def test_archive_api_refuses_incomplete_scan(tmp_path):
    _, scan, manifest = source(tmp_path)
    manifest['summary']['missing_target_count'] = 1
    with pytest.raises(ArchiveError, match='target'):
        write_archive(archive_path=tmp_path / 'incomplete.zip', archive_format='zip',
                      manifest=manifest, files=scan.files)
    assert not (tmp_path / 'incomplete.zip').exists()


@pytest.mark.parametrize('fmt', ['zip', 'tar'])
@pytest.mark.parametrize('paths', [
    ['report?.txt'], ['CON.txt'], ['A.txt', 'a.txt'], ['nested', 'nested/one.txt'],
])
def test_archive_writer_refuses_paths_that_readers_cannot_restore(tmp_path, fmt, paths):
    from dataclasses import replace
    _, scan, manifest = source(tmp_path)
    files = tuple(replace(scan.files[0], rel_path=path) for path in paths)
    out = tmp_path / 'backups'
    archive = out / ('unsafe.zip' if fmt == 'zip' else 'unsafe.tar.gz')
    with pytest.raises(ArchiveError):
        write_archive(archive_path=archive, archive_format=fmt, manifest=manifest, files=files)
    assert not archive.exists()
    assert not out.exists() or not list(out.iterdir())


@pytest.mark.parametrize('fmt', ['zip', 'tar'])
def test_posix_backup_refuses_unrestorable_scanned_names(tmp_path, capsys, fmt):
    import os
    from verified_backup.cli import main
    if os.name == 'nt':
        pytest.skip('POSIX filenames require a case-sensitive POSIX filesystem')
    for index, names in enumerate([['report?.txt'], ['CON.txt'], ['A.txt', 'a.txt']]):
        root = tmp_path / f'source-{index}'
        root.mkdir()
        for name in names:
            (root / name).write_bytes(b'synthetic')
        scan = scan_source(root.resolve(), load_rules())
        assert {item.rel_path for item in scan.files} == set(names)
        out = tmp_path / f'backups-{index}'
        assert main(['backup', '--root', str(root), '--output-dir', str(out),
                     '--format', fmt, '--name', 'unsafe']) == 2
        assert json.loads(capsys.readouterr().err)['ok'] is False
        assert not out.exists() or not list(out.iterdir())


def test_scan_output_never_clobbers_existing_source_file(tmp_path, capsys):
    from verified_backup.cli import main
    root, _, _ = source(tmp_path)
    out = root / 'one.txt'
    assert main(['scan', '--root', str(root), '--output', str(out)]) == 2
    assert out.read_bytes() == b'one'


@pytest.mark.parametrize('path', [
    'keep.txt:evil', 'dir:stream/a', 'C:escape', 'CON', 'nul.txt',
    'dir/COM1.log', 'dir/lpt9', 'trailing.', 'trailing ', 'a/../b',
    '/absolute', 'a//b', 'a/./b', r'a\b', 'a\x00b', '',
])
def test_noncanonical_or_windows_unsafe_paths_are_rejected_everywhere(tmp_path, path):
    from verified_backup.paths import safe_join
    from verified_backup.verify import payload_rel, verify_archive
    from verified_backup.restore import restore_archive
    with pytest.raises(ValueError):
        safe_join(tmp_path / 'dest', path)
    with pytest.raises(ArchiveError):
        payload_rel('payload/' + path)
    archive = synthetic_archive(tmp_path, [entry(path)], [])
    with pytest.raises(ArchiveError):
        verify_archive(archive)
    with pytest.raises(ArchiveError):
        restore_archive(archive_path=archive, dest=tmp_path / 'dest')
    assert not (tmp_path / 'dest').exists()


@pytest.mark.parametrize('prefix', ['', 'nested/', 'nested/deeper/'])
def test_default_credentials_are_excluded_at_every_depth(tmp_path, prefix):
    root = tmp_path / 'synthetic'
    names = ['.netrc', '.pgpass', '.npmrc', '.pypirc', 'auth.json', 'server.ppk',
             'release.jks', 'app.keystore', 'wallet.dat', '.git-credentials',
             '.ssh/config', '.gnupg/config', '.aws/config', '.kube/config',
             '.docker/config.json']
    for name in [*names, 'keep.txt']:
        path = root / (prefix + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'synthetic only')
    scan = scan_source(root.resolve(), load_rules())
    assert [item.rel_path for item in scan.files] == [prefix + 'keep.txt']
    assert len(scan.excluded) == len(names)


def test_metadata_is_redacted_by_default_with_explicit_local_opt_in(tmp_path, capsys):
    from verified_backup.cli import main
    from verified_backup.restore import restore_archive, RestoreSafetyError
    root, _, _ = source(tmp_path)
    (root / 'sensitive-secret-name.txt').write_bytes(b'synthetic')
    for fmt in ('zip', 'tar'):
        out = tmp_path / fmt
        assert main(['backup', '--root', str(root), '--output-dir', str(out),
                     '--format', fmt, '--name', 'safe']) == 0
        result = json.loads(capsys.readouterr().out)
        manifest = json.loads(Path(result['manifest']).read_text(encoding='utf-8'))
        text = json.dumps(manifest)
        assert root.as_posix() not in text
        assert 'sensitive-secret-name' not in text
        assert 'rules' not in manifest
        assert manifest['excluded_counts'] == {'secret_name': 1}
        with pytest.raises(RestoreSafetyError):
            restore_archive(archive_path=Path(result['archive']), dest=root, execute=True)
        from verified_backup.verify import read_embedded_manifest
        assert read_embedded_manifest(Path(result['archive'])) == manifest
    private = tmp_path / 'private.json'
    assert main(['scan', '--root', str(root), '--output', str(private),
                 '--include-private-metadata']) == 0
    capsys.readouterr()
    details = json.loads(private.read_text(encoding='utf-8'))
    assert details['source_root'] == root.as_posix()
    assert details['excluded'][0]['path'] == 'sensitive-secret-name.txt'


@pytest.mark.parametrize('fmt', ['zip', 'tar'])
def test_verify_rejects_size_metadata_mismatch(tmp_path, fmt):
    from verified_backup.verify import verify_archive
    archive = synthetic_archive(tmp_path, [entry(size=999)],
                                [('payload/nested/one.txt', b'one')], fmt)
    result = verify_archive(archive)
    assert result['ok'] is False
    assert any('size' in error.lower() for error in result['errors'])


@pytest.mark.parametrize('case', ['top-list', 'schema', 'files-null', 'entry-null',
                                  'path-missing', 'size-missing', 'negative-size',
                                  'boolean-size', 'float-size', 'hash-missing', 'bad-hash'])
def test_manifest_fields_fail_cleanly_before_restore_writes(tmp_path, capsys, case):
    from verified_backup.cli import main
    manifest = {'schema_version': 'verified-backup-manifest/v1', 'files': [entry()]}
    if case == 'top-list':
        manifest = []
    elif case == 'schema':
        manifest['schema_version'] = 'unknown'
    elif case == 'files-null':
        manifest['files'] = None
    elif case == 'entry-null':
        manifest['files'] = [None]
    else:
        item = manifest['files'][0]
        if case.endswith('-missing'):
            del item[{'path-missing': 'path', 'size-missing': 'size', 'hash-missing': 'sha256'}[case]]
        elif case == 'bad-hash':
            item['sha256'] = 'not-a-sha256'
        else:
            item['size'] = {'negative-size': -1, 'boolean-size': True, 'float-size': 3.0}[case]
    archive = tmp_path / 'malformed.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('BACKUP_MANIFEST.json', json.dumps(manifest))
        zf.writestr('payload/nested/one.txt', b'one')
    assert main(['verify', str(archive)]) == 2
    assert json.loads(capsys.readouterr().err)['ok'] is False
    dest = tmp_path / 'never'
    assert main(['restore', str(archive), '--dest', str(dest), '--execute']) == 2
    assert json.loads(capsys.readouterr().err)['ok'] is False
    assert not dest.exists()


def test_verify_rejects_sidecar_size_mismatch(tmp_path):
    from verified_backup.verify import verify_archive
    _, scan, manifest = source(tmp_path)
    archive = tmp_path / 'backup.zip'
    manifest = write_archive(archive_path=archive, archive_format='zip', manifest=manifest, files=scan.files)
    _, checksums = write_sidecar_manifests(archive_path=archive, manifest=manifest)
    data = json.loads(checksums.read_text())
    data['files'][0]['size'] += 1
    checksums.write_text(json.dumps(data))
    assert verify_archive(archive, checksums)['ok'] is False


@pytest.mark.parametrize('fmt', ['zip', 'tar'])
def test_ads_payload_cannot_touch_existing_file(tmp_path, fmt):
    from verified_backup.restore import restore_archive
    archive = synthetic_archive(tmp_path, [entry('keep.txt:evil')],
                                [('payload/keep.txt:evil', b'one')], fmt)
    dest = tmp_path / 'dest'
    dest.mkdir()
    keep = dest / 'keep.txt'
    keep.write_bytes(b'untouched')
    for execute in (False, True):
        with pytest.raises(ArchiveError):
            restore_archive(archive_path=archive, dest=dest, execute=execute)
    assert keep.read_bytes() == b'untouched'
    assert not (dest / 'keep.txt:evil').exists()
    assert list(dest.iterdir()) == [keep]


def test_example_exercises_review_safety_defaults():
    import os
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env['PYTHONPATH'] = str(repo / 'src')
    proc = subprocess.run([sys.executable, '-B', str(repo / 'examples/end_to_end_demo.py')],
                          cwd=repo, env=env, text=True, encoding='utf-8', capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for marker in ('metadata redacted', 'private scan', 'repeat backup refused',
                   'nested output refused', 'missing target refused', 'DEMO PASS'):
        assert marker in proc.stdout


@pytest.mark.parametrize('fmt', ['zip', 'tar'])
@pytest.mark.parametrize('case', ['duplicate-payload', 'duplicate-manifest', 'extra', 'missing',
                                  'outside', 'case-collision', 'file-parent'])
def test_inventory_is_rejected_by_verify_and_restore_before_writes(tmp_path, fmt, case):
    from verified_backup.verify import verify_archive
    from verified_backup.restore import restore_archive
    entries = [entry()]
    payloads = [('payload/nested/one.txt', b'one')]
    if case == 'duplicate-payload':
        payloads *= 2
    elif case == 'duplicate-manifest':
        payloads.append(('BACKUP_MANIFEST.json', json.dumps({
            'schema_version': 'verified-backup-manifest/v1', 'files': entries}).encode()))
    elif case == 'extra':
        payloads.append(('payload/extra.txt', b'one'))
    elif case == 'missing':
        payloads = []
    elif case == 'outside':
        payloads.append(('ignored.txt', b'one'))
    elif case == 'case-collision':
        entries.append(entry('nested/ONE.txt'))
        payloads.append(('payload/nested/ONE.txt', b'one'))
    elif case == 'file-parent':
        entries.append(entry('nested'))
        payloads.append(('payload/nested', b'one'))
    with pytest.warns(UserWarning) if fmt == 'zip' and case.startswith('duplicate') else __import__('contextlib').nullcontext():
        archive = synthetic_archive(tmp_path, entries, payloads, fmt)
    try:
        assert verify_archive(archive)['ok'] is False
    except ArchiveError:
        pass
    for execute in (False, True):
        dest = tmp_path / f'dest-{execute}'
        with pytest.raises(ArchiveError):
            restore_archive(archive_path=archive, dest=dest, execute=execute)
        assert not dest.exists()

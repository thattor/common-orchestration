# tests/test_release_tools.py — release tooling: golden + hostile cases.
"""Determinism, exact flat-root inventory, hostile archives, binds.

A real temp git repo at the flattened runtime_v4 root supplies real
SHAs; working-tree mutation after the commit cannot enter the build and
manifest constants come only from the SHA's blobs. Adapter IDs are the
actual ones (antigravity.text.only, t3code.orchestration-v2, ...).
Malicious members are fixtures only. No qualification, key or provider
claims; phase-D evidence is elsewhere.
"""
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent / 'tools'
sys.path.insert(0, str(TOOLS))
import build_release as br          # noqa: E402
import verify_release as vr         # noqa: E402

ERR = br.ReleaseError
PREFIX = 'common-orchestration-v0.4.4'
BASE = Path('.')


def git(repo, *args):
    out = subprocess.run(['git', '-C', str(repo)] + list(args),
                         check=True, capture_output=True)
    return out.stdout


def put(repo, rel, blob):
    path = repo / BASE / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def commit(repo):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.email=t@t', '-c', 'user.name=t',
        'commit', '-qm', 'x')
    return git(repo, 'rev-parse', 'HEAD').decode().strip()


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.repo = self.dir / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        put(self.repo, 'VERSION', b'0.4.4\n')
        put(self.repo, 'README.md', b'# readme\n')
        put(self.repo, 'RUNBOOK.md', b'# runbook\n')
        put(self.repo, 'LICENSE.md', b'synthetic license\n')
        put(self.repo, 'NOTICE', b'synthetic notice\n')
        put(self.repo, 'examples/host.example.json', b'{}\n')
        put(self.repo, 'examples/templates/PROVENANCE', b'upstream\n')
        put(self.repo, 'examples/templates/LICENSE-Apache-2.0',
            b'Apache License\n')
        put(self.repo, 'skills/co-task/SKILL.md',
            b'---\nname: co-task\n'
            b'description: Run one CO task goal.\n---\n# co-task\n')
        put(self.repo, 'co_v4/__init__.py', b'MARK = 1\n')
        put(self.repo, 'co_v4/state.py',
            b"CONTRACT_MARKER = 'co.controller/4'\n"
            b"CONTROLLER_VERSION = '4.0.0'\n")
        # All seven real adapter modules with their ACTUAL adapter ids;
        # OpenAI 0.1.0, copied Native adapters 0.2.0-dev.
        for name, adapter, version in (
                ('openai_responses', 'openai.responses', '0.1.0'),
                ('openai_chat', 'openai.chat', '0.1.0'),
                ('claude', 'claude.print', '0.2.0-dev'),
                ('codex', 'codex.app-server', '0.2.0-dev'),
                ('devin', 'devin.acp', '0.2.0-dev'),
                ('antigravity', 'antigravity.text.only', '0.2.0-dev'),
                ('t3code', 't3code.orchestration-v2', '0.2.0-dev')):
            put(self.repo, 'co_v4/adapters/' + name + '.py',
                ("ADAPTER = '%s'\nADAPTER_VERSION = '%s'\n"
                 % (adapter, version)).encode())
        put(self.repo, 'co_v4/t3code_rpc.mjs', b'// rpc\n')
        for rel in ('run_ci_tests.py', 'requirements-sdk-test.txt',
                    'model-lifecycle.example.json', 'ADAPTER-CONCURRENCY.md',
                    'MODEL-LIFECYCLE.md', 'probes/p.py',
                    'tests/test_x.py', 'tools/build_release.py'):
            put(self.repo, rel, b'x\n')
        self.sha = commit(self.repo)

    @staticmethod
    def _env(endpoint, auth_ref, digest):
        body = json.dumps({'endpoint': endpoint, 'auth_ref': auth_ref,
            'profile_digest': digest}, sort_keys=True,
            separators=(',', ':')).encode()
        return 'env:sha256:' + hashlib.sha256(
            b'co.env/1\n' + body).hexdigest()

    def _tested(self, protocol, digest):
        env = self._env('http://127.0.0.1:50353/v1', 'prov-key', digest)
        return {'product': 'llama.cpp',
                'provider_build': 'b11429',
                'provider_commit': 'a' * 40, 'model_id': 'm',
                'model_sha256': 'b' * 64,
                'chat_template_sha256': 'c' * 64,
                'provider_manifest_sha256': 'd' * 64,
                'protocols': [protocol],
                'profile_digest': digest,
                'endpoint': 'http://127.0.0.1:50353/v1',
                'auth_ref': 'prov-key',
                'environment_ref': env}

    def evidence(self):
        natives = {'readiness': 'unqualified', 'native_tested': []}
        return {'git_sha': self.sha, 'tag': PREFIX,
                'adapters': {
                    'openai.responses': {'controller_compat': '4.0.0',
                        'readiness': 'qualified',
                        'native_tested': [
                            self._tested('responses', '1' * 64)]},
                    'openai.chat': {'controller_compat': '4.0.0',
                        'readiness': 'qualified',
                        'native_tested': [
                            self._tested('chat', '2' * 64)]},
                    'claude.print': dict(natives),
                    'codex.app-server': dict(natives),
                    'devin.acp': dict(natives),
                    'antigravity.text.only': dict(natives),
                    't3code.orchestration-v2': dict(natives,
                        unsupported=[
                            {'path': 'co_v4/t3code_rpc.mjs',
                             'ref': 'native-unqualified'}])},
                'sdk': {'openai': '3.24.0', 'httpx': '0.28.1'},
                'python_versions': ['3.11', '3.12', '3.13'],
                'darwin': {'version': '27.0.0', 'arch': 'arm64'}}


class ArchiveTests(Fixture):
    def test_deterministic_dirty_tree_and_nested_prefix(self):
        one = self.dir / 'a.tar.gz'
        result = br.build(str(self.repo), self.sha, str(one))
        first = one.read_bytes()
        (self.repo / BASE / 'VERSION').write_bytes(b'9.9.9\n')
        (self.repo / BASE / 'junk.gguf').write_bytes(b'x')
        (self.repo / BASE / 'skills/co-task/SKILL.md').write_bytes(
            b'MUTATED\n')
        two = self.dir / 'b.tar.gz'
        self.assertEqual(br.build(str(self.repo), self.sha, str(two)),
                         result)
        self.assertEqual(two.read_bytes(), first)
        with tarfile.open(str(one), 'r:gz') as tar:
            members = tar.getmembers()
            skill = tar.extractfile(
                PREFIX + '/skills/co-task/SKILL.md').read()
        self.assertEqual(skill, git(
            self.repo, 'show',
            self.sha + ':skills/co-task/SKILL.md'))
        # Globally lexicographically sorted; bare normalized root dir.
        self.assertEqual(members[0].name, PREFIX)
        self.assertTrue(members[0].isdir() and members[0].mode == 0o755
                        and members[0].uid == 0 and members[0].gid == 0
                        and members[0].uname == ''
                        and members[0].gname == '')
        self.assertEqual([m.name for m in members],
                         sorted(m.name for m in members))
        self.assertTrue(all(m.name == PREFIX
                            or m.name.startswith(PREFIX + '/')
                            for m in members))
        files = sorted(m.name[len(PREFIX) + 1:] for m in members
                       if m.isfile())
        self.assertEqual(files, sorted(result['files']))
        self.assertIn('co_v4/adapters/t3code.py', files)
        self.assertNotIn('co_v4/t3code_rpc.mjs', files)
        self.assertFalse(any(f.split('/')[0]
                             in ('tests', 'probes', 'tools')
                             for f in files))

    def test_unknown_missing_and_injection_refused(self):
        for rel in ('co_v4/key.pem', 'assets/model.gguf',
                    'co_v4/data.sqlite', 'OTHER.md', 'co_v4/x.txt'):
            with self.subTest(rel=rel):
                put(self.repo, rel, b'x')
                sha = commit(self.repo)
                with self.assertRaises(ERR):
                    br.build(str(self.repo), sha,
                             str(self.dir / 'x.tgz'))
        (self.repo / BASE / 'RUNBOOK.md').unlink()
        sha = commit(self.repo)
        with self.assertRaises(ERR):
            br.build(str(self.repo), sha, str(self.dir / 'x.tgz'))
        for bad in ('HEAD', 'main', 'x' * 39, 'a' * 40 + ';rm', '', None):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ERR):
                    br.build(str(self.repo), bad, str(self.dir / 'x.tgz'))


    def test_excluded_dir_named_blob_refused(self):
        # A top-level BLOB named like an excluded directory is unknown
        # inventory — it must refuse, never be silently skipped as if
        # it were the excluded directory itself.
        for name in ('tools', 'probes', 'tests'):
            with self.subTest(name=name):
                for child in (self.repo / BASE / name).iterdir():
                    child.unlink()
                (self.repo / BASE / name).rmdir()
                put(self.repo, name, b'x')
                sha = commit(self.repo)
                with self.assertRaises(ERR):
                    br.build(str(self.repo), sha, str(self.dir / 'x.tgz'))

    def test_required_skill_missing_refused(self):
        # A clean commit without the declared Skill refuses: a missing
        # declared member is never silently dropped.
        (self.repo / BASE / 'skills/co-task/SKILL.md').unlink()
        sha = commit(self.repo)
        with self.assertRaises(ERR):
            br.build(str(self.repo), sha, str(self.dir / 'x.tgz'))

    def test_required_legal_missing_refused(self):
        # A clean commit without either declared legal file refuses: a
        # missing declared member is never silently dropped.
        for rel, blob in (('LICENSE.md', b'synthetic license\n'),
                          ('NOTICE', b'synthetic notice\n')):
            path = self.repo / BASE / rel
            with self.subTest(missing=rel):
                path.unlink()
                try:
                    sha = commit(self.repo)
                    with self.assertRaises(ERR):
                        br.build(str(self.repo), sha,
                                 str(self.dir / 'x.tgz'))
                finally:
                    path.write_bytes(blob)
                    commit(self.repo)

    def test_unexpected_skill_sibling_refused(self):
        # An extra blob under skills/ is unknown inventory; there is no
        # skills/ allowlist and unknown files anywhere refuse.
        put(self.repo, 'skills/co-task/REFERENCE.md', b'x')
        sha = commit(self.repo)
        with self.assertRaises(ERR):
            br.build(str(self.repo), sha, str(self.dir / 'x.tgz'))

class ManifestTests(Fixture):
    def _archive(self):
        path = self.dir / (PREFIX + '.tar.gz')
        br.build(str(self.repo), self.sha, str(path))
        return path

    def test_sha_bound_constants_rehash_and_adapters(self):
        archive = self._archive()
        (self.repo / BASE / 'VERSION').write_bytes(b'9.9.9\n')
        (self.repo / BASE / 'co_v4' / 'state.py').write_bytes(
            b"CONTROLLER_VERSION = '9.9.9'\n")
        manifest = br.generate_manifest(str(self.repo), self.sha,
                                        self.evidence(), str(archive))
        self.assertEqual(manifest['co_version'], '0.4.4')
        self.assertEqual(manifest['controller'],
                         {'version': '4.0.0',
                          'contract': 'co.controller/4'})
        self.assertEqual(set(manifest), br.MANIFEST_KEYS)
        self.assertEqual(manifest['archive_sha256'],
                         hashlib.sha256(archive.read_bytes()).hexdigest())
        # Independently recompute one blob hash from the same SHA: the
        # manifest map must equal the real git object, not the caller.
        blob = git(self.repo, 'show',
                   self.sha + ':co_v4/state.py').decode()
        self.assertEqual(manifest['files']['co_v4/state.py'],
                         hashlib.sha256(blob.encode()).hexdigest())
        # All seven real adapters ship with their actual ids; OpenAI
        # qualified with its OWN protocol entry, every Native
        # unqualified with no test record.
        self.assertEqual(set(manifest['adapters']), {
            'openai.responses', 'openai.chat', 'claude.print',
            'codex.app-server', 'devin.acp', 'antigravity.text.only',
            't3code.orchestration-v2'})
        responses = manifest['adapters']['openai.responses']
        chat = manifest['adapters']['openai.chat']
        self.assertEqual(responses['version'], '0.1.0')
        self.assertEqual(responses['native_tested'][0]['protocols'],
                         ['responses'])
        self.assertEqual(chat['native_tested'][0]['protocols'],
                         ['chat'])
        self.assertNotEqual(
            responses['native_tested'][0]['environment_ref'],
            chat['native_tested'][0]['environment_ref'])
        self.assertEqual(
            responses['native_tested'][0]['environment_ref'],
            self._env('http://127.0.0.1:50353/v1', 'prov-key',
                      '1' * 64))
        for adapter_id in ('claude.print', 'codex.app-server',
                           'devin.acp', 'antigravity.text.only',
                           't3code.orchestration-v2'):
            record = manifest['adapters'][adapter_id]
            self.assertEqual(record['version'], '0.2.0-dev')
            self.assertEqual(record['readiness'], 'unqualified')
            self.assertEqual(record['native_tested'], [])
            self.assertNotIn('controller_compat', record)

    def test_mismatches_and_missing_version_refused(self):
        archive = self._archive()
        for mutate in (
                lambda ev: ev.update(git_sha='0' * 40),
                lambda ev: ev.update(tag='other-v0.4.4'),
                lambda ev: ev['adapters'].pop('t3code.orchestration-v2'),
                lambda ev: ev['adapters']['t3code.orchestration-v2']
                    .update(native_tested=[{'x': 1}]),
                # Shared binding: chat reuses the responses-derived env.
                lambda ev: ev['adapters']['openai.chat']
                    ['native_tested'].__setitem__(
                        0, self._tested('chat', '1' * 64)),
                # environment_ref that does not derive refuses.
                lambda ev: ev['adapters']['openai.responses']
                    ['native_tested'][0].update(
                        environment_ref='env:sha256:' + '9' * 64),
                # Second entry under one adapter refuses (exactly one).
                lambda ev: ev['adapters']['openai.responses']
                    ['native_tested'].append(
                        self._tested('responses', '3' * 64)),
                # Responses may never carry a chat entry.
                lambda ev: ev['adapters']['openai.responses']
                    ['native_tested'].__setitem__(
                        0, self._tested('chat', '4' * 64)),
                # A copied Native can never be caller-qualified —
                # fabricated readiness refuses even with a valid
                # measured-entry shape.
                lambda ev: ev['adapters']['claude.print'].update(
                    readiness='qualified',
                    native_tested=[self._tested('chat', '5' * 64)]),
                lambda ev: ev.update(python_versions=['3.x'])):
            ev = self.evidence()
            mutate(ev)
            with self.assertRaises(ERR):
                br.generate_manifest(str(self.repo), self.sha, ev,
                                     str(archive))
        # A real adapter module without ADAPTER_VERSION fails closed.
        (self.repo / BASE / 'co_v4' / 'adapters'
         / 'claude.py').write_bytes(b"ADAPTER = 'claude.print'\n")
        sha = commit(self.repo)
        ev = self.evidence()
        ev['git_sha'] = sha
        with self.assertRaises(ERR):
            br.generate_manifest(str(self.repo), sha, ev, str(archive))

    def test_archive_binding_exact_bytes_refused(self):
        archive = self._archive()
        manifest = br.generate_manifest(str(self.repo), self.sha,
                                        self.evidence(), str(archive))
        self.assertEqual(manifest['archive_sha256'],
                         hashlib.sha256(archive.read_bytes()).hexdigest())
        # Mutated archive bytes refuse even at syntactically valid size.
        blob = bytearray(archive.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        mutated = self.dir / 'mutated.tar.gz'
        mutated.write_bytes(bytes(blob))
        with self.assertRaises(ERR):
            br.generate_manifest(str(self.repo), self.sha,
                                 self.evidence(), str(mutated))
        # A valid archive built from a DIFFERENT commit refuses binding
        # to this SHA — generation never blesses foreign source bytes.
        (self.repo / BASE / 'README.md').write_bytes(b'# changed\n')
        sha2 = commit(self.repo)
        other = self.dir / 'other.tar.gz'
        br.build(str(self.repo), sha2, str(other))
        with self.assertRaises(ERR):
            br.generate_manifest(str(self.repo), self.sha,
                                 self.evidence(), str(other))
        # An arbitrary tarball with no relation to the SHA refuses.
        foreign = self.dir / 'foreign.tar.gz'
        with open(foreign, 'wb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                               mtime=0) as gz:
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode='w') as tar:
                    info = tarfile.TarInfo('x.py')
                    info.size = 2
                    tar.addfile(info, io.BytesIO(b'ok'))
                gz.write(buf.getvalue())
        with self.assertRaises(ERR):
            br.generate_manifest(str(self.repo), self.sha,
                                 self.evidence(), str(foreign))


class VerifyTests(Fixture):
    def _assets(self):
        archive = self.dir / (PREFIX + '.tar.gz')
        br.build(str(self.repo), self.sha, str(archive))
        manifest = br.generate_manifest(str(self.repo), self.sha,
                                        self.evidence(), str(archive))
        (self.dir / 'RELEASE-MANIFEST.json').write_bytes(
            json.dumps(manifest).encode())
        self.manifest = manifest
        (self.dir / 'SHA256SUMS').write_text(
            '%s  %s\n%s  RELEASE-MANIFEST.json\n' % (
                manifest['archive_sha256'], archive.name,
                hashlib.sha256((self.dir / 'RELEASE-MANIFEST.json')
                               .read_bytes()).hexdigest()))
        return archive

    def _tar(self, members, name='evil'):
        path = self.dir / (name + '-%d.tar.gz' % len(members))
        with open(path, 'wb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                               mtime=0) as gz:
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w') as tar:
                    for mname, kind, data in members:
                        info = tarfile.TarInfo(mname)
                        if kind == 'file':
                            info.size = len(data)
                            tar.addfile(info, io.BytesIO(data))
                        elif kind == 'link':
                            info.type = tarfile.SYMTYPE
                            info.linkname = data
                            tar.addfile(info)
                        else:
                            info.type = tarfile.DIRTYPE
                            tar.addfile(info)
                gz.write(buffer.getvalue())
        return path

    def test_roundtrip_extract_and_isolated_import(self):
        archive = self._assets()
        manifest = vr.verify_assets(str(self.dir))
        dest = self.dir / 'out'
        dest.mkdir()
        vr.extract(str(archive), manifest, str(dest))
        self.assertTrue((dest / 'co_v4' / 'state.py').is_file())
        vr.import_check(str(dest))         # -I bootstrap, all adapters
        no_pkg = self.dir / 'no-package'
        no_pkg.mkdir()
        with self.assertRaises(ERR):
            vr.import_check(str(no_pkg))   # no co_v4 at that root

    def test_hostile_members_and_destinations_refused(self):
        manifest = {'prefix': PREFIX,
                    'files': {'x.py': hashlib.sha256(b'ok').hexdigest()}}
        base = PREFIX + '/'
        cases = [
            [('/abs/x.py', 'file', b'ok')],
            [(base + '../x.py', 'file', b'ok')],
            [(base + 'x.py', 'link', '/etc/passwd')],
            [(base + 'x.py', 'file', b'bad')],
            [(base + 'x.py', 'file', b'ok'),
             (base + 'x.py', 'file', b'ok')],           # duplicate file
            [(base + 'x.py', 'file', b'ok'),
             (base + 'y.py', 'file', b'ok')],           # extra member
            [(base + 'x.py', 'file', b'ok'),
             (base + 'evil', 'dir', b'')],              # undeclared dir
        ]
        for i, members in enumerate(cases):
            with self.subTest(case=i):
                dest = self.dir / ('d%d' % i)
                dest.mkdir()
                with self.assertRaises(ERR):
                    vr.extract(str(self._tar(members, 'e%d' % i)),
                               manifest, str(dest))
                self.assertEqual(list(dest.iterdir()), [])
        # Duplicate DIRECTORY entries refuse too (manifest declares a
        # 'd' dir via files {'d/x.py'}).
        deep = {'prefix': PREFIX,
                'files': {'d/x.py': hashlib.sha256(b'ok').hexdigest()}}
        dup_dir = self._tar([(base + 'd', 'dir', b''),
                             (base + 'd', 'dir', b'')], 'dd')
        dest = self.dir / 'dd'
        dest.mkdir()
        with self.assertRaises(ERR):
            vr.extract(str(dup_dir), deep, str(dest))
        busy = self.dir / 'busy'
        busy.mkdir()
        (busy / 'x').symlink_to('/etc')
        good = self._tar([(base + 'x.py', 'file', b'ok')], 'g')
        with self.assertRaises(ERR):
            vr.extract(str(good), manifest, str(busy))
        linkdest = self.dir / 'linkdest'
        linkdest.symlink_to(self.dir / 'out2', target_is_directory=True)
        (self.dir / 'out2').mkdir()
        with self.assertRaises(ERR):
            vr.extract(str(good), manifest, str(linkdest))

    def test_canonical_inventory_refusals_and_positive_extract(self):
        self._assets()
        digest = hashlib.sha256(b'ok').hexdigest()
        z_hash = hashlib.sha256(b'z').hexdigest()
        loaded = str(self.dir / 'RELEASE-MANIFEST.json')
        self.assertEqual(vr.load_manifest(loaded)['prefix'], PREFIX)
        base = PREFIX + '/'
        tar_two = self._tar([(base + 'x.py', 'file', b'ok'),
                             (base + 'y.py', 'file', b'ok')], 'two')
        cases = (
            {'./x.py': digest}, {'a/./x.py': digest},
            {'a/../x.py': digest}, {'../x.py': digest},
            {'/x.py': digest}, {'x.py/': digest},
            {'a//x.py': digest}, {'a\\x.py': digest},
            {'\x00x.py': digest},
            # duplicate file keys: case / normalization aliases
            {'x.py': digest, 'X.PY': digest},
            {'X.PY': digest, 'x.py': digest},
            {'caf\u00e9.py': digest, 'cafe\u0301.py': digest},
            # file-as-ancestor: both orders, case + NFC/NFD variants
            {'a.py': digest, 'a.py/x.py': digest},
            {'a.py/x.py': digest, 'a.py': digest},
            {'A.PY': digest, 'a.py/x.py': digest},
            {'a.py/x.py': digest, 'A.PY': digest},
            {'caf\u00e9': digest, 'cafe\u0301/x.py': digest},
            {'cafe\u0301/x.py': digest, 'caf\u00e9': digest},
            # one prefix key, different spellings: both orders
            {'A/x.py': digest, 'a/y.py': digest},
            {'a/y.py': digest, 'A/x.py': digest},
            {'caf\u00e9/x.py': digest, 'cafe\u0301/y.py': digest},
            {'cafe\u0301/y.py': digest, 'caf\u00e9/x.py': digest},
        )
        for i, files in enumerate(cases):
            with self.subTest(case=i):
                manifest = dict(self.manifest, files=files)
                dest = self.dir / ('n%d' % i)
                dest.mkdir()
                with self.assertRaises(ERR):        # direct extract
                    vr.extract(str(tar_two), manifest, str(dest))
                self.assertTrue(dest.is_dir())      # exists, empty
                self.assertEqual(list(dest.iterdir()), [])
                bad = self.dir / ('bad%d.json' % i)
                bad.write_bytes(json.dumps(manifest).encode())
                with self.assertRaises(ERR):        # loaded manifest
                    vr.load_manifest(str(bad))
        # Positive control: distinct canonical names extract normally.
        tar_ok = self._tar([(base + 'x.py', 'file', b'ok'),
                            (base + 'd/z.py', 'file', b'z')], 'ok')
        manifest = dict(self.manifest,
                        files={'x.py': digest, 'd/z.py': z_hash})
        dest = self.dir / 'ok'
        dest.mkdir()
        vr.extract(str(tar_ok), manifest, str(dest))
        self.assertEqual((dest / 'x.py').read_bytes(), b'ok')
        self.assertEqual((dest / 'd' / 'z.py').read_bytes(), b'z')
    def test_sums_duplicate_hex_extra_and_tamper_refused(self):
        archive = self._assets()
        self.assertTrue(vr.verify_assets(str(self.dir)))
        sums = self.dir / 'SHA256SUMS'
        text = sums.read_text()
        sums.write_text(text + text.splitlines()[0] + '\n')
        with self.assertRaises(ERR):
            vr.verify_assets(str(self.dir))
        sums.write_text('zz' + '0' * 62 + '  x.tar.gz\n')
        with self.assertRaises(ERR):
            vr.verify_assets(str(self.dir))
        sums.write_text(text + 'a' * 64 + '  extra.bin\n')
        with self.assertRaises(ERR):
            vr.verify_assets(str(self.dir))
        sums.write_text(text)
        tampered = dict(self.manifest,
            files=dict(self.manifest['files'],
                       **{'co_v4/__init__.py': '0' * 64}))
        dest = self.dir / 't'
        dest.mkdir()
        with self.assertRaises(ERR):       # same inventory, wrong hash
            vr.extract(str(archive), tampered, str(dest))
        # Files map must bind the real blob content, not the input.
        self.assertNotEqual(self.manifest['files']['co_v4/__init__.py'],
                            '0' * 64)

    def test_argv_and_semantic_comparators(self):
        argv = ('srv', '-m', '/m/m.gguf', '--chat-template-file', '/a/t',
                '--api-key-file', '/a/k', '--host', '127.0.0.1',
                '--port', '8000', '--threads', '2')
        fresh = tuple('/b/t' if p == '/a/t' else
                      '/b/k' if p == '/a/k' else
                      '9000' if p == '8000' else p for p in argv)
        self.assertTrue(vr.argv_semantics_equal(argv, fresh))
        for bad in (
                # Forbidden mutations: model path, host, extra flag,
                # thread count — port/path changes remain the only
                # permitted normalizations and are never relaxed.
                tuple('/m/other.gguf' if p == '/m/m.gguf' else p
                      for p in fresh),
                tuple('0.0.0.0' if p == '127.0.0.1' else p
                      for p in fresh),
                argv + ('--temp', '1'),
                tuple('4' if p == '2' else p for p in fresh)):
            self.assertFalse(vr.argv_semantics_equal(argv, bad))
        release = {'protocol': 'responses', 'index_mode': 'present',
                   'sequence_mode': 'present', 'inert_fields': {},
                   'model': 'm', 'provider_manifest_sha256': 'a' * 64}
        fresh_profile = dict(release, provider_manifest_sha256='b' * 64)
        self.assertTrue(
            vr.profile_semantics_equal(release, fresh_profile))
        self.assertFalse(vr.profile_semantics_equal(
            release, dict(fresh_profile,
                          index_mode='absent_single_part')))
        # Missing fields fail closed — absent-vs-absent is not equal.
        self.assertFalse(vr.profile_semantics_equal(release, {}))
        self.assertFalse(vr.profile_semantics_equal({}, {}))
        doc = {'provider_build': 'b', 'provider_commit': 'x',
               'model_id': 'm', 'model_sha256': 'h',
               'launch': {'argv': list(argv), 'chat_template_sha256': 't',
                          'slots': 1, 'threads': 2},
               'qualification': {'sdk_version': '3.24.0',
                                 'auth_results': {'valid': 200}},
               'assertions': {'a': {'passed': True}},
               'multipart': {'kind': 'source_evidence'}}
        fresh_doc = json.loads(json.dumps(doc))
        fresh_doc['launch']['argv'] = list(fresh)
        self.assertTrue(vr.manifest_semantics_equal(doc, fresh_doc))
        fresh_doc['launch']['threads'] = 4
        self.assertFalse(vr.manifest_semantics_equal(doc, fresh_doc))
        broken = dict(doc)
        del broken['launch']
        self.assertFalse(vr.manifest_semantics_equal(broken, fresh_doc))
        self.assertFalse(vr.manifest_semantics_equal({}, {}))


if __name__ == '__main__':
    unittest.main()

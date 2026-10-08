"""Host-side admission for task inference calls.

One private host root (passwd home + '.co-task-host') holds per-cwd gate
flocks and the canonical CapacityLedger. Each supported route maps to a fixed
adapter name sharing a global limit of 12 unresolved leases across every task
state dir and model. Leases are keyed 'task-cwd:<sha256>' / 'setup-cwd:<sha256>'
in ref.run_id so no extra tables are needed.

Known limitations:
- The host path is fixed; a separately configured service ledger does not
  auto-share capacity (only the identical ledger file does).
- No OS-level containment or remote-cancellation guarantee is provided.
- Missing stop proof, parent death, or orphaned reserved/executing leases hold
  capacity until a future evidence-based recovery; there is no supported reset
  or force-release path.
"""
import hashlib
import os
import pwd
import sqlite3
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .. import contracts as c
from ..adapter_capacity import MAX_CONCURRENT, CapacityLedger
from ..state import body_digest
from .common import PrivateFileLock, RouteFailure, TaskError, canonical, digest

_ROUTES = {'claude': 'claude.print', 'devin': 'devin.acp'}
_ROOT_NAME = '.co-task-host'
_LEDGER = 'capacity.db'
_EV_STOP = 'task-admission:stop-confirmed'
_EV_NOCHILD = 'task-admission:spawn-no-child'

_CURRENT = ContextVar('co_v4_task_admission_gate', default=None)


@dataclass(frozen=True)
class _Conditions:
    adapter: str


@dataclass(frozen=True)
class _Request:
    ref: c.AttemptRef
    conditions: _Conditions
    model_digest: str
    input_digest: str
    binding_digest: str


@dataclass(frozen=True)
class _Gate:
    cwd: Path
    kind: str
    scope: str
    binding: object
    ledger: CapacityLedger
    root: Path


def _host_root() -> Path:
    """Canonical passwd-derived host root. Tests may patch this resolver.

    Ignores HOME/XDG/environment/state; no CLI or env override exists.
    """
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve() / _ROOT_NAME


def _lexical_root() -> Path:
    """Unresolved host root spelling: absolute path with a canonical parent.

    Kept lexical so a hostile or accidental symlink at the final component is
    caught by lstat instead of silently followed by resolve().
    """
    root = Path(_host_root())
    if not root.is_absolute():
        raise TaskError('capacity_invalid')
    try:
        canonical_parent = Path(os.path.realpath(root.parent))
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if root.parent != canonical_parent:
        raise TaskError('capacity_invalid')
    return root


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fsync_dir(path: Path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_root(root: Path):
    """Create 0700 host root or revalidate a private one. Never repairs."""
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    else:
        os.chmod(root, 0o700)
        _fsync_dir(root.parent)
    try:
        st = root.lstat()
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700):
        raise TaskError('capacity_invalid')


def _emit(path: Path, payload: dict, *, create: bool = False):
    """Write 0600 JSON evidence atomically; never overwrites unsafe files.

    create stages a unique temp then installs it with an exclusive hardlink,
    so a preexisting admission.json is refused instead of replaced. Updates
    first revalidate the live file (0600, owner, single link, regular, no
    symlink) and only then atomically replace it.
    """
    data = canonical(payload).encode()
    tmp = path.with_name(f'{path.name}.{uuid4().hex}.tmp')
    try:
        fd = os.open(tmp,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        _quiet(os.unlink, tmp)
        raise TaskError('capacity_invalid') from exc
    try:
        if create:
            os.link(tmp, path)
        else:
            st = path.lstat()
            if (not stat.S_ISREG(st.st_mode)
                    or st.st_uid != os.getuid()
                    or stat.S_IMODE(st.st_mode) != 0o600
                    or st.st_nlink != 1):
                raise TaskError('capacity_invalid')
            os.replace(tmp, path)
        _fsync_dir(path.parent)
    except TaskError:
        raise
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    finally:
        _quiet(os.unlink, tmp)


def _quiet(fn, *args):
    try:
        fn(*args)
    except BaseException:
        pass


@contextmanager
def gate(cwd, *, state_dir=None, setup=False, binding=None):
    """Per-cwd fingerprint gate: SH flock normally, EX for setup.

    While held, durable setup rows for this cwd block normal entry and any
    held task/setup row blocks setup entry, even after a SIGKILL lost the
    parent's flock. Ordinary task leases never block other tasks. Exit releases
    only the flock, never ambiguous leases.
    """
    try:
        base = Path(cwd).resolve(strict=True)
        if not base.is_dir():
            raise TaskError('capacity_invalid')
        extra = Path(state_dir).resolve(strict=True) if state_dir is not None else None
        root = _lexical_root()
    except TaskError:
        raise
    except (OSError, RuntimeError) as exc:
        raise TaskError('capacity_invalid') from exc
    for other in (base, extra):
        if other is not None and (root == other or root in other.parents
                                  or other in root.parents):
            raise TaskError('capacity_invalid')
    _ensure_root(root)
    try:
        ledger = CapacityLedger(root / _LEDGER)
    except Exception as exc:
        raise TaskError('capacity_invalid') from exc
    scope = hashlib.sha256(str(base).encode()).hexdigest()
    lock = PrivateFileLock(root / f'gate-{scope}.lock',
                           busy_code='route_busy', shared=not setup)
    with lock:
        try:
            rows = ledger.unresolved()
        except Exception as exc:
            raise TaskError('capacity_invalid') from exc
        held = set()
        for snap in rows:
            if snap.ref.run_id == f'task-cwd:{scope}':
                held.add('task')
            elif snap.ref.run_id == f'setup-cwd:{scope}':
                held.add('setup')
        if (setup and held) or (not setup and 'setup' in held):
            raise TaskError('route_busy')
        token = _CURRENT.set(_Gate(base, 'setup' if setup else 'task',
                                   scope, binding, ledger, root))
        try:
            yield _CURRENT.get()
        finally:
            _CURRENT.reset(token)


def model_call(route, model, prompt, call_dir, invoke, *, before_launch=None):
    """One admitted inference call inside a matching gate scope.

    Reserves the shared adapter slot before invoke; full capacity raises
    'capacity_full' with no queue, retry, or route switch. Claim is durably
    committed inside the launch hook before _spawn's Popen; release happens
    only after confirmed group cleanup (or proven no-child spawn failure).
    """
    g = _CURRENT.get()
    if g is None:
        raise TaskError('capacity_invalid', 'gate context required')
    adapter = _ROUTES.get(route)
    if adapter is None:
        raise RouteFailure('route_unavailable', 'not_started', 'preflight')
    raw = Path(call_dir)
    if not raw.is_absolute():
        raise TaskError('capacity_invalid', 'call dir must be absolute')
    try:
        cdir = raw.resolve(strict=True)
        cst = cdir.lstat()
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if (raw != cdir or stat.S_ISLNK(cst.st_mode)
            or not stat.S_ISDIR(cst.st_mode)
            or cst.st_uid != os.getuid()
            or stat.S_IMODE(cst.st_mode) != 0o700):
        raise TaskError('capacity_invalid', 'unsafe call dir')
    for protected in (g.cwd, g.root):
        if (cdir == protected or protected in cdir.parents
                or cdir in protected.parents):
            raise TaskError('capacity_invalid',
                            'call dir overlaps protected path')
    try:
        binding_digest = body_digest(g.binding)
    except Exception as exc:
        raise TaskError('capacity_invalid') from exc
    text = prompt.encode() if isinstance(prompt, str) else bytes(prompt)
    request = _Request(
        ref=c.AttemptRef(
            f'{g.kind}-cwd:{g.scope}',
            'call-' + hashlib.sha256(str(cdir).encode()).hexdigest(),
            uuid4().hex),
        conditions=_Conditions(adapter),
        model_digest=digest(str(model).encode()),
        input_digest=digest(text),
        binding_digest=binding_digest)
    owner = 'owner-' + uuid4().hex
    try:
        if not g.ledger.reserve(request, owner):
            raise TaskError('capacity_full')
    except TaskError:
        raise
    except Exception as exc:
        raise TaskError('capacity_invalid') from exc
    evp = cdir / 'admission.json'
    ev = {'v': 1, 'route': route, 'model': model,
          'request_digest': body_digest(request),
          'binding_digest': binding_digest,
          'reserved_at': _now(), 'claimed_at': None,
          'stopped_at': None, 'confirmed': False}
    try:
        _emit(evp, ev, create=True)
    except TaskError:
        _quiet(g.ledger.release_reserved, request, owner)
        raise

    claimed = released = False
    launches = 0
    stopped_calls = []

    def _before():
        nonlocal claimed, launches
        launches += 1
        if launches > 1:
            raise TaskError('capacity_invalid', 'launch hook repeated')
        if before_launch is not None:
            before_launch()
        try:
            g.ledger.claim(request, owner)
        except Exception as exc:
            raise TaskError('capacity_invalid') from exc
        claimed = True
        try:
            ev['claimed_at'] = _now()
            _emit(evp, ev)
        except BaseException:
            _quiet(g.ledger.release, request, owner, _EV_NOCHILD)
            raise

    def _stopped(ok):
        nonlocal released
        if not claimed:
            raise TaskError('capacity_invalid', 'stop hook before claim')
        if stopped_calls:
            raise TaskError('capacity_invalid', 'stop hook repeated')
        if not isinstance(ok, bool):
            raise TaskError('capacity_invalid', 'stop proof must be bool')
        stopped_calls.append(ok)
        ev['stopped_at'] = _now()
        ev['confirmed'] = ok is True
        _emit(evp, ev)
        if ok is True:
            try:
                g.ledger.release(request, owner, _EV_STOP)
            except Exception as exc:
                raise TaskError('capacity_invalid') from exc
            released = True

    try:
        result = invoke(before_launch=_before, on_stopped=_stopped)
    except BaseException as exc:
        if (claimed and type(exc) is RouteFailure
                and exc.code == 'route_unavailable'
                and exc.outcome == 'not_started' and exc.phase == 'spawn'):
            _quiet(_emit, evp, ev)
            _quiet(g.ledger.release, request, owner, _EV_NOCHILD)
        elif not claimed:
            _quiet(g.ledger.release_reserved, request, owner)
        raise
    if launches != 1:
        if not claimed:
            _quiet(g.ledger.release_reserved, request, owner)
        raise TaskError('capacity_invalid', 'launch hook did not run once')
    if stopped_calls != [True] or not released:
        raise TaskError('route_stop_unconfirmed')
    return result


def capacity_status() -> dict:
    """Sanitized per-route lease counts. Never creates host root or ledger.

    'executing' counts are UNCONFIRMED lease holds, not proof of live children.
    initialized=False means genuinely absent state only; existing but unsafe,
    unreadable, mismatched, or corrupt state raises capacity_invalid.
    """
    empty = {'initialized': False, 'limit': MAX_CONCURRENT, 'routes': {}}
    root = _lexical_root()
    dbp = root / _LEDGER
    try:
        rst = root.lstat()
    except FileNotFoundError:
        return empty
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if (stat.S_ISLNK(rst.st_mode) or not stat.S_ISDIR(rst.st_mode)
            or rst.st_uid != os.getuid()
            or stat.S_IMODE(rst.st_mode) != 0o700):
        raise TaskError('capacity_invalid')
    try:
        st = dbp.lstat()
    except FileNotFoundError:
        return empty
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1):
        raise TaskError('capacity_invalid')
    try:
        db = sqlite3.connect(dbp.as_uri() + '?mode=ro', uri=True)
        try:
            cfg = db.execute('SELECT version, maximum FROM capacity_config').fetchall()
            rows = db.execute(
                "SELECT adapter, phase, count(*) FROM adapter_leases "
                "WHERE phase!='released' GROUP BY adapter, phase").fetchall()
        finally:
            db.close()
    except Exception as exc:
        raise TaskError('capacity_invalid') from exc
    if len(cfg) != 1 or tuple(cfg[0]) != (2, MAX_CONCURRENT):
        raise TaskError('capacity_invalid')
    try:
        st2 = dbp.lstat()
    except OSError as exc:
        raise TaskError('capacity_invalid') from exc
    if (st2.st_ino, st2.st_dev) != (st.st_ino, st.st_dev):
        raise TaskError('capacity_invalid')
    reverse = {v: k for k, v in _ROUTES.items()}
    routes = {r: {'reserved': 0, 'executing': 0} for r in _ROUTES}
    for adapter, phase, n in rows:
        if phase not in ('reserved', 'executing'):
            continue
        key = reverse.get(adapter, adapter)
        routes.setdefault(key, {'reserved': 0, 'executing': 0})[phase] = n
    return {'initialized': True, 'limit': MAX_CONCURRENT, 'routes': routes}

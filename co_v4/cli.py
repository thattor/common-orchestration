"""co_v4/cli.py — bounded host entry: `python -m co_v4 --config <abs>`.

Phase A: load_host_config() validates the closed document; the runtime
builder is the trusted composition seam — this module never opens
manifests, credentials or routes itself. SIGINT/SIGTERM handlers only set
an Event and are installed BEFORE host.start(), so a startup signal is
still a graceful stop. The loop waits for the Event, then close() until
'stopped': an unconfirmed close logs the fixed code, keeps the owner
flock/stores/leases held, and retries with bounded backoff — the process
never exits while a writer is unconfirmed. A global failure latches
unavailable (503) and the process still waits for a signal. No fork, no
daemon, no force kill; handlers are restored on exit.
"""
import argparse
import signal
import sys
import time
from threading import Event

from .host_config import load_host_config
from .host_runtime import build as _runtime_build
from .service_host import ServiceHost

CODE_FAILED = 'host_start_failed'
CODE_UNCONFIRMED = 'host_stop_unconfirmed'
STOPPED = 'stopped'
BACKOFF = (1.0, 2.0, 4.0, 8.0, 10.0)


def _parser():
    parser = argparse.ArgumentParser(prog='co_v4')
    parser.add_argument('--config', required=True)
    return parser


def main(argv=None, *, load=load_host_config, build=_runtime_build,
         host_type=ServiceHost, sleep=time.sleep, err=None):
    """Run the host lifecycle; returns a process exit code. The callable
    seams exist for trusted-Python tests only — never config-selectable."""
    err = sys.stderr if err is None else err
    args = _parser().parse_args(argv)
    try:
        config = load(args.config)
    except Exception:
        err.write(CODE_FAILED + '\n')
        return 1
    stop = Event()

    def mark(*_args):
        stop.set()

    previous = {sig: signal.signal(sig, mark)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        try:
            # ServiceHost owns partial-failure teardown; nothing foreign
            # is closed when the builder or constructor refuses.
            host = host_type(config.state_root, build(config))
        except Exception:
            err.write(CODE_FAILED + '\n')
            return 1
        failed = False
        try:
            host.start()
        except Exception:
            # start() already ran teardown: close() below confirms or
            # retries it; exit is nonzero either way once stopped.
            failed = True
        else:
            # Latch-only global failure keeps the process alive here;
            # only a signal moves it to the close loop.
            stop.wait()
        index = 0
        while host.close() != STOPPED:
            err.write(CODE_UNCONFIRMED + '\n')
            sleep(BACKOFF[min(index, len(BACKOFF) - 1)])
            index += 1
        if failed:
            err.write(CODE_FAILED + '\n')
            return 1
        return 0
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)

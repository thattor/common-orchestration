"""Isolated-install test driver. Never installed as a product entry point."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

# Only the copied fixture directory is exposed here. Product import must resolve
# through the disposable venv's explicit .pth activation, never source PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixture_e2e import Scenario
from co_v4 import contracts as c


def main(mode, directory):
    h = Scenario(directory, create=mode not in ('reopen', 'continue'), callback=mode == 'stop', models=('fixture-a',))
    try:
        result = {'module': c.__file__, 'prefix': sys.prefix}
        if mode == 'pending':
            assert h.step().reason == 'next_job'
            result['executions'] = len(h.adapter.requests)
        elif mode in ('complete', 'continue'):
            if mode == 'continue': h.controller = h.build()
            final = h.drive()
            assert final.state == c.State.COMPLETED
            result.update(controller_state=final.state.value, checks=len(h.checks))
        elif mode == 'stop':
            h.step(); h.step()
            h.confirm = True
            assert h.step().state == c.State.WAITING_HUMAN
            wait = h.current_wait()
            h.publish(wait)
            h.receive(wait, h.comment(wait, 'stop_run'))
            held = h.step()
            # Confirmed cessation without a Result holds truthfully: no
            # Result, AC or output is fabricated and the Run stays non-terminal.
            assert (held.state, held.reason, held.cessation_confirmed) == \
                (c.State.RUNNING, 'stop_result_missing', True)
            attempt = h.state.get_attempt(h.adapter.requests[0].ref)
            assert attempt.result is None and attempt.ac is None
            assert attempt.output is None
            assert h.state.get_run('run').state not in c.TERMINAL
            h.adapter.finish(h.adapter.requests[0].ref)  # genuine Result
            final = h.step()
            assert (final.state, final.reason, final.cessation_confirmed) == \
                (c.State.FAILED, 'human_stop', True)
            result.update(controller_state=final.state.value, cessation_confirmed=True,
                          executions=len(h.adapter.requests))
        elif mode == 'reopen':
            recovered = h.build().step()
            assert recovered.state == h.state.get_run('run').state
            assert not h.adapter.requests
            result['recovery'] = recovered.state.value
        else:
            raise ValueError('unknown driver mode')
        result.update(durable_state=h.state.get_run('run').state.value,
                      stop_requested=h.state.get_run('run').stop_requested,
                      ac_count=len(h.state.history('run', 'ac_history')),
                      trace_count=len(h.trace.records()))
        return result
    finally:
        h.close()


if __name__ == '__main__':
    with patch('socket.socket', side_effect=AssertionError('no network in fixture')), \
         patch('subprocess.Popen', side_effect=AssertionError('no Native process in fixture')):
        print(json.dumps(main(*sys.argv[1:])))

"""Run the offline CI gate from a file so multiprocessing spawn can re-import it."""

import os
import unittest


def main():
    suite = unittest.defaultTestLoader.discover('tests', pattern='test*.py')

    def cases(node):
        for item in node:
            if isinstance(item, unittest.TestSuite):
                yield from cases(item)
            else:
                yield item

    counts = {'unit': 0, 'contract': 0, 'integration': 0}
    for test in cases(suite):
        module = test.id().split('.')[0]
        group = {'test_contracts': 'contract', 'test_controller': 'integration'}.get(module, 'unit')
        counts[group] += 1
    print(f'Discovered tests: {counts}', flush=True)
    if not all(counts.values()):
        raise SystemExit('Missing unit, Contract or Controller integration tests; refusing an empty gate')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    executed = result.testsRun - len(result.skipped)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write(f'- Discovery: {counts}\n- Run: {result.testsRun}; skipped: {len(result.skipped)}; failures: {len(result.failures)}; errors: {len(result.errors)}\n')
    if not executed or not result.wasSuccessful():
        raise SystemExit(1)


# Spawn imports this file as __mp_main__; only the original process runs tests.
if __name__ == "__main__":
    main()

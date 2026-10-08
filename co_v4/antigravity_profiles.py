"""Exact AGY launch candidates, separate from Native/Controller qualification.

A listed candidate only defines an invocation and source pin. Current offering,
authentication, credits/quota, context and privacy still require trusted host
preflight. Global CLI effort syntax never expands this per-model allowlist.
"""
from dataclasses import dataclass

LEGACY_BINARY_SHA = 'd15693410c904242c1c3423a579f60a81e018444bb51fbccc6505f988b62a91d'
CURRENT_BINARY_SHA = '7dca095cfc1df2c057a385ed88a76c7ba98dc103258a80be87a8f42e484cb3aa'
LEGACY_MODEL = 'gemini-3.8-flash-high'
# CLI 1.2.16 `agy models`, observed 2026-10-04. These are candidates,
# not automatic Catalog entries and not transferred 1.2.15 qualification.
_CURRENT_PAIRS = frozenset(
    (f'claude-{family}-5-5-{effort}', effort)
    for family in ('opus', 'sonnet') for effort in ('low', 'medium', 'high'))


@dataclass(frozen=True)
class AntigravityRouteProfile:
    model: str
    effort: str
    native_version: str

    def __post_init__(self):
        if not ((self.model, self.effort, self.native_version) == (LEGACY_MODEL, 'high', '1.2.15')
                or (self.native_version == '1.2.16' and (self.model, self.effort) in _CURRENT_PAIRS)):
            raise ValueError('unsupported exact AGY model/effort/version')

    @property
    def binary_sha256(self):
        return LEGACY_BINARY_SHA if self.native_version == '1.2.15' else CURRENT_BINARY_SHA

    @property
    def plan_expansion(self):
        # Both exact binaries have independent static framing evidence.
        return True

    @property
    def native_done_lf(self):
        return True


LEGACY_ROUTE = AntigravityRouteProfile(LEGACY_MODEL, 'high', '1.2.15')
CANDIDATE_ROUTES = tuple(AntigravityRouteProfile(model, effort, '1.2.16')
                         for model, effort in sorted(_CURRENT_PAIRS))

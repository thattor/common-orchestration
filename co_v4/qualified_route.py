"""Host-owned qualification gate for profile-bound OpenAI-compatible routes.

Per design/0.4/OPENAI-COMPATIBLE-EDGES.md (qualified route profile ruling):
before any transport open or POST the gate re-verifies the host's own
manifest and raw evidence through the injected reader, re-issues the route
profile from that verified manifest via issue_profile() (protocol capture
check included) and requires the canonical profile digest to equal the
host-configured profile — a caller-constructed profile, verified object or
digest alone is never authority. Observable identity (served model id and
any exposed build/commit) must match the manifest; unobservable argv,
model-file and template identity is host attestation through the injected
launch_attested() callback, never runtime proof. Callbacks receive only
detached canonical views so no reader or callback can move the verified
comparison. Any mismatch excludes the route's environment identity for
the life of this gate — no requalification, no warning-only mode. Routes
without a profile keep the generic strict default and never enter this
gate; Worker, client and model input can select none of host paths,
config or evidence.
"""
from dataclasses import dataclass

from .protocol_profile import (ProfileError, RouteProtocolProfile,
    environment_ref, issue_profile, verify_manifest)

OBSERVED_KEYS = frozenset({'model', 'build', 'commit'})


@dataclass(frozen=True)
class QualifiedBinding:
    """Immutable pre-POST identity evidence for one qualified route.

    attestation records that the host's launch_attested() callback checked
    this route — a host attestation for unobservable fields, not a runtime
    proof."""
    endpoint: str
    auth_ref: str
    model: str
    environment_ref: str
    profile: RouteProtocolProfile
    manifest_sha256: str
    attestation: str = 'host_launched_manifest_argv'


class QualifiedRouteGate:
    """Process-lifetime exclusion gate; every check fails closed."""

    def __init__(self, *, read_evidence, probe_identity, launch_attested=None):
        # read_evidence(path)->bytes loads host-configured evidence files.
        # probe_identity()->dict returns only nonsecret observable identity.
        # launch_attested(manifest_fields, endpoint, auth_ref)->True exactly:
        # the trusted host attests this endpoint's provider was launched from
        # the manifest argv/model/template with that credential reference.
        if (not callable(read_evidence) or not callable(probe_identity)
                or not callable(launch_attested)):
            raise ProfileError('gate requires host readers')
        self._read, self._probe = read_evidence, probe_identity
        self._attest = launch_attested
        self._excluded = set()

    def exclude(self, environment_ref):
        """Host-deny-only latch for preflight failures outside qualify():
        adds the environment identity to the same process-lifetime
        exclusion set. Idempotent; there is no reset or un-exclude API."""
        self._excluded.add(environment_ref
                           if type(environment_ref) is str else '<unknown>')

    def qualify(self, *, profile, manifest, endpoint, auth_ref, request):
        """Return a QualifiedBinding or raise ProfileError; any failure
        latches the route's environment identity excluded for this process."""
        env = getattr(getattr(request, 'conditions', None),
                      'environment_ref', None)
        key = env if type(env) is str else '<unknown>'
        if key in self._excluded:
            raise ProfileError('route excluded')
        try:
            binding = self._qualify(profile, manifest, endpoint,
                                    auth_ref, request)
        except ProfileError:
            self._excluded.add(key)
            raise
        except Exception:
            self._excluded.add(key)
            raise ProfileError('qualification failed') from None
        return binding

    def _qualify(self, profile, manifest, endpoint, auth_ref, request):
        if type(profile) is not RouteProtocolProfile:
            raise ProfileError('profile invalid')
        verified = verify_manifest(manifest, self._read)
        issued = issue_profile(verified, profile.protocol,
            index_mode=profile.index_mode,
            sequence_mode=profile.sequence_mode,
            inert_fields=profile.inert_fields)
        if issued.profile_digest != profile.profile_digest:
            raise ProfileError('profile mismatch')
        if auth_ref != verified.manifest['auth']['credential_ref']:
            raise ProfileError('auth_ref mismatch')
        try:
            # Detached manifest view: the callback cannot move sealed data.
            attested = self._attest(verified.manifest, endpoint, auth_ref)
        except Exception:
            raise ProfileError('launch attestation failed') from None
        if attested is not True:
            raise ProfileError('launch attestation failed')
        # Fresh parse after the callback: any mutation it made is gone.
        fields = verified.manifest
        conditions = getattr(request, 'conditions', None)
        if (conditions is None
                or conditions.model != issued.model
                or conditions.adapter != 'openai.' + issued.protocol):
            raise ProfileError('request binding mismatch')
        env = environment_ref(endpoint, auth_ref, issued.profile_digest)
        if env != conditions.environment_ref:
            raise ProfileError('environment_ref mismatch')
        try:
            observed = self._probe()
        except Exception:
            raise ProfileError('identity probe failed') from None
        if (type(observed) is not dict
                or not set(observed) <= OBSERVED_KEYS
                or type(observed.get('model')) is not str):
            raise ProfileError('identity probe invalid')
        if (observed['model'] != issued.model
                or ('build' in observed
                    and observed['build'] != fields['provider_build'])
                or ('commit' in observed
                    and observed['commit'] != fields['provider_commit'])):
            raise ProfileError('observed identity mismatch')
        return QualifiedBinding(endpoint=endpoint, auth_ref=auth_ref,
            model=issued.model, environment_ref=env, profile=issued,
            manifest_sha256=verified.manifest_sha256)

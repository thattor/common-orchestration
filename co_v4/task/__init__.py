"""co_v4.task — scoped one-shot task runner: shared contracts and durable outputs.

Submodules carry the fixed TaskError codes; this package only re-exports the
common primitives so callers do not depend on module layout.
"""
from .common import TaskError, canonical, digest, parse_json, private_dir

__all__ = ['TaskError', 'canonical', 'digest', 'parse_json', 'private_dir']

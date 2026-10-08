"""Static prior-fit presets for native candidates (profile co04-199-prior-v1).

Data only: exact (route, model) identities plus maintainer-provisional ordinal
fit preferences. These ratings were informed by consultations that included
the rated models themselves; they are not cross-validated and are not a local
benchmark. They are registered only after a successful native measurement and
never imply a role-to-model mapping.
"""

PROFILE_ID = "co04-199-prior-v1"

ORIGIN = "prior"

SOURCE_REF = ("https://github.com/thattor/ai-company/issues/199"
              "#issuecomment-6049204846")

PRESETS = (
    {
        "route": "claude",
        "model": "claude-opus-5-5",
        "fit": {
            "architecture_planning": 3,
            "reasoning": 3,
            "writing": 3,
            "coding": 2,
            "review": 3,
            "general": 2,
        },
    },
    {
        "route": "devin",
        "model": "swe-2-high",
        "fit": {
            "coding": 3,
            "review": 2,
            "architecture_planning": 2,
            "reasoning": 2,
            "writing": 1,
            "general": 2,
        },
    },
)


def known(route, model):
    """Return the preset record for an exact (route, model), or None."""
    for preset in PRESETS:
        if preset["route"] == route and preset["model"] == model:
            return preset
    return None


def fit_entries(route, model):
    """Fresh prior fit attestation entries for a known preset, else []."""
    preset = known(route, model)
    if preset is None:
        return []
    return [
        {"category": category, "degree": degree,
         "origin": ORIGIN, "source_ref": SOURCE_REF}
        for category, degree in preset["fit"].items()
    ]

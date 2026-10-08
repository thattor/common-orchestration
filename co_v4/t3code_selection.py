"""Exact selection from a trusted, current T3 provider advertisement.

``default`` means T3's advertised recommendation, not its permission ``auto``
mode or an autonomous model router. Advertisement is not live qualification.
"""
from dataclasses import dataclass
import hashlib
import json


def _text(value):
    return type(value) is str and 0 < len(value.encode()) <= 256 and value == value.strip()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def advertised_models(config, instance_id='codex'):
    """Return a bounded sanitized catalog; never expose auth/settings values."""
    providers = config.get('providers') if type(config) is dict else None
    if type(providers) is not list or len(providers) > 64 or not _text(instance_id):
        raise ValueError('invalid T3 provider catalog')
    matches = [p for p in providers if type(p) is dict and p.get('instanceId') == instance_id]
    if len(matches) != 1:
        raise ValueError('T3 provider identity is ambiguous')
    provider = matches[0]
    if provider.get('enabled') is not True or provider.get('status') != 'ready':
        raise ValueError('T3 provider is not ready')
    models = provider.get('models')
    if type(models) is not list or not 0 < len(models) <= 256:
        raise ValueError('invalid T3 model catalog')
    result, seen = [], set()
    for model in models:
        if type(model) is not dict or not _text(model.get('slug')) or model['slug'] in seen:
            raise ValueError('invalid or duplicate T3 model')
        seen.add(model['slug'])
        if type(model.get('isDefault', False)) is not bool:
            raise ValueError('invalid T3 default flag')
        capabilities = model.get('capabilities')
        descriptors = capabilities.get('optionDescriptors') if type(capabilities) is dict else None
        if type(descriptors) is not list or len(descriptors) > 64:
            raise ValueError('invalid T3 option descriptors')
        options, ids = {}, set()
        for descriptor in descriptors:
            if type(descriptor) is not dict or not _text(descriptor.get('id')) or descriptor['id'] in ids:
                raise ValueError('invalid or duplicate T3 option descriptor')
            ids.add(descriptor['id'])
            if descriptor['id'] not in ('reasoningEffort', 'serviceTier'):
                continue
            values = descriptor.get('options')
            if descriptor.get('type') != 'select' or type(values) is not list or not 0 < len(values) <= 32:
                raise ValueError('invalid T3 selectable options')
            choices, defaults = [], []
            for value in values:
                if (type(value) is not dict or not _text(value.get('id')) or value['id'] in choices
                        or type(value.get('isDefault', False)) is not bool):
                    raise ValueError('invalid or duplicate T3 option')
                choices.append(value['id'])
                if value.get('isDefault') is True:
                    defaults.append(value['id'])
            current = descriptor.get('currentValue')
            if current is not None and (not _text(current) or current not in choices):
                raise ValueError('unadvertised T3 option default')
            if len(defaults) > 1 or (defaults and current is not None and defaults[0] != current):
                raise ValueError('ambiguous T3 option default')
            options[descriptor['id']] = {'values': choices,
                'default': current if current is not None else (defaults[0] if defaults else None)}
        result.append({'model': model['slug'], 'is_default': model.get('isDefault', False), 'options': options})
    return result


@dataclass(frozen=True)
class T3Selection:
    mode: str
    instance_id: str
    model: str
    effort: str
    service_tier: str
    catalog_sha256: str

    def descriptor(self):
        return dict(mode=self.mode, instance_id=self.instance_id, model=self.model,
            effort=self.effort, service_tier=self.service_tier, catalog_sha256=self.catalog_sha256)

    def profile(self, request, project_id, human_intent_ref):
        from .adapters.t3code import T3Profile
        if request.conditions.model != self.model:
            raise ValueError('request differs from resolved T3 model')
        options = [{'id': 'reasoningEffort', 'value': self.effort},
                   {'id': 'serviceTier', 'value': self.service_tier}]
        return T3Profile(request, project_id, self.instance_id, human_intent_ref,
            json.dumps(options), selection_mode=self.mode, selection_ref=self.catalog_sha256)

    def verify_current(self, config):
        current = resolve_selection(config, instance_id=self.instance_id, mode=self.mode,
            model=self.model if self.mode == 'explicit' else None,
            effort=self.effort if self.mode == 'explicit' else None,
            service_tier=self.service_tier)
        if current != self:
            raise ValueError('T3 advertised selection changed')


def resolve_selection(config, *, instance_id='codex', mode='default', model=None,
                      effort=None, service_tier='default'):
    """Resolve before constructing ExecuteRequest; no fuzzy IDs or silent fallback."""
    if mode not in ('default', 'explicit') or not _text(service_tier):
        raise ValueError('invalid T3 selection mode')
    catalog = advertised_models(config, instance_id)
    if mode == 'default':
        if model is not None or effort is not None:
            raise ValueError('T3 default selection cannot contain explicit overrides')
        defaults = [m for m in catalog if m['is_default']]
        if len(defaults) != 1:
            raise ValueError('T3 default model is missing or ambiguous')
        selected = defaults[0]
        effort = selected['options'].get('reasoningEffort', {}).get('default')
        model = selected['model']
    else:
        selected = next((m for m in catalog if m['model'] == model), None)
        if selected is None:
            raise ValueError('exact T3 model is not advertised')
    if not _text(effort) or effort not in selected['options'].get('reasoningEffort', {}).get('values', []):
        raise ValueError('exact T3 effort is not advertised')
    if service_tier not in selected['options'].get('serviceTier', {}).get('values', []):
        raise ValueError('exact T3 service tier is not advertised')
    return T3Selection(mode, instance_id, model, effort, service_tier, _digest(catalog))

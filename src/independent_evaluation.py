"""Validate external capture/evidence manifests without assigning or scoring labels."""
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath

from .common import sha256


SHA256 = re.compile(r'^[0-9a-f]{64}$')
REQUIRED_SESSION = {
    'session_id', 'capture_path', 'capture_sha256', 'capture_start_epoch', 'capture_end_epoch',
    'environment_id', 'receiver_id', 'independent_from_development', 'authorized_testbed',
    'evidence', 'devices', 'intervals'
}


def _decimal(value, field, errors):
    try:
        result = Decimal(str(value))
        if not result.is_finite():
            raise InvalidOperation
        return result
    except (InvalidOperation, ValueError):
        errors.append(f'{field}: invalid finite decimal timestamp')
        return None


def _relative_file(project, value, field, expected_hash, errors):
    posix = PurePosixPath(str(value).replace('\\', '/'))
    if posix.is_absolute() or '..' in posix.parts or str(posix) in ('', '.'):
        errors.append(f'{field}: path must be a safe project-relative path')
        return None
    path = project.joinpath(*posix.parts)
    if not path.is_file():
        errors.append(f'{field}: file not found: {posix}')
        return None
    if not isinstance(expected_hash, str) or not SHA256.fullmatch(expected_hash):
        errors.append(f'{field}: invalid SHA256 declaration')
    elif sha256(path) != expected_hash:
        errors.append(f'{field}: SHA256 mismatch')
    return path


def validate_session(session, project_root, protocol):
    """Return validation facts; never derive ground truth from packet fields."""
    project = Path(project_root).resolve(); errors = []; warnings = []
    missing = sorted(REQUIRED_SESSION - set(session))
    if missing:
        errors.append(f'missing session fields: {missing}')
    session_id = str(session.get('session_id', ''))
    if not session_id or session_id.startswith('REPLACE_'):
        errors.append('session_id: missing or placeholder')
    capture_hash = session.get('capture_sha256', '')
    _relative_file(project, session.get('capture_path', ''), 'capture_path', capture_hash, errors)
    if capture_hash in protocol['development_capture_sha256s']:
        errors.append('capture is byte-identical to a development capture')
    if session.get('independent_from_development') is not True:
        errors.append('independent_from_development must be explicitly true')
    if protocol['require_authorized_testbed'] and session.get('authorized_testbed') is not True:
        errors.append('authorized_testbed must be explicitly true')
    start = _decimal(session.get('capture_start_epoch'), 'capture_start_epoch', errors)
    end = _decimal(session.get('capture_end_epoch'), 'capture_end_epoch', errors)
    if start is not None and end is not None and start >= end:
        errors.append('capture timestamp range is empty or reversed')

    evidence = {}; evidence_types = set(protocol['allowed_evidence_types'])
    for item in session.get('evidence', []):
        identifier = str(item.get('evidence_id', ''))
        if not identifier or identifier in evidence:
            errors.append(f'evidence_id missing or duplicated: {identifier!r}'); continue
        evidence[identifier] = item
        if item.get('type') not in evidence_types:
            errors.append(f'{identifier}: unsupported evidence type')
        _relative_file(project, item.get('path', ''), f'evidence {identifier}', item.get('sha256', ''), errors)

    devices = {}; roles = set(protocol['verified_roles'])
    for device in session.get('devices', []):
        identifier = str(device.get('device_id', ''))
        if not identifier or identifier in devices:
            errors.append(f'device_id missing or duplicated: {identifier!r}'); continue
        devices[identifier] = device
        if device.get('ground_truth_role') not in roles:
            errors.append(f'{identifier}: role is not independently verified')
        cited = device.get('evidence_ids', [])
        if not cited or any(value not in evidence for value in cited):
            errors.append(f'{identifier}: missing or unknown identity evidence')

    countable_roles = set(); countable_intervals = 0
    interval_ids = set(); scenarios = set(protocol['allowed_scenarios'])
    for interval in session.get('intervals', []):
        identifier = str(interval.get('interval_id', ''))
        if not identifier or identifier in interval_ids:
            errors.append(f'interval_id missing or duplicated: {identifier!r}'); continue
        interval_ids.add(identifier)
        left = _decimal(interval.get('start_epoch'), f'{identifier}.start_epoch', errors)
        right = _decimal(interval.get('end_epoch'), f'{identifier}.end_epoch', errors)
        if left is not None and right is not None:
            if left >= right: errors.append(f'{identifier}: empty or reversed interval')
            if start is not None and end is not None and (left < start or right > end):
                errors.append(f'{identifier}: outside capture range')
        scenario = interval.get('scenario')
        if scenario not in scenarios:
            errors.append(f'{identifier}: unsupported scenario')
        cited_devices = interval.get('device_ids', [])
        cited_evidence = interval.get('evidence_ids', [])
        if not cited_devices or any(value not in devices for value in cited_devices):
            errors.append(f'{identifier}: missing or unknown devices')
        if not cited_evidence or any(value not in evidence for value in cited_evidence):
            errors.append(f'{identifier}: missing or unknown event evidence')
        countable = interval.get('ground_truth_scope') == protocol['countable_ground_truth_scope']
        if scenario == 'ssid_bssid_clone' and protocol['cloned_bssid_requires_frame_attribution']:
            attribution = interval.get('frame_attribution_evidence_id')
            if not countable or attribution not in evidence:
                countable = False
                warnings.append(f'{identifier}: cloned-BSSID interval is not countable without external frame attribution')
        if countable and all(value in devices for value in cited_devices):
            countable_roles.update(devices[value].get('ground_truth_role', 'unknown') for value in cited_devices)
            countable_intervals += 1

    if not session.get('intervals'):
        warnings.append('no ground-truth intervals declared')
    return {
        'session_id': session_id,
        'valid': not errors,
        'errors': errors,
        'warnings': warnings,
        'capture_sha256': capture_hash,
        'countable_verified_roles': sorted(countable_roles),
        'countable_interval_count': countable_intervals,
    }


def readiness(registry, sessions, project_root, protocol):
    if registry.get('schema_version') != 1:
        raise ValueError('Unsupported independent registry schema')
    results = [validate_session(session, project_root, protocol) for session in sessions]
    identifiers = [r['session_id'] for r in results]
    duplicates = sorted({value for value in identifiers if identifiers.count(value) > 1})
    hashes = [r['capture_sha256'] for r in results]
    duplicate_hashes = sorted({value for value in hashes if hashes.count(value) > 1})
    counts = {role: len({r['capture_sha256'] for r in results
                        if r['valid'] and role in r['countable_verified_roles']})
              for role in protocol['verified_roles']}
    minimum = protocol['minimum_independent_sessions_per_class']
    gate = not duplicates and not duplicate_hashes and all(r['valid'] for r in results) and all(value >= minimum for value in counts.values())
    return {
        'status': 'ready_for_frozen_independent_scoring' if gate else 'blocked_waiting_for_independent_evidence',
        'scoring_authorized_by_data_gate': gate,
        'session_manifest_count': len(results),
        'valid_session_count': sum(r['valid'] for r in results),
        'duplicate_session_ids': duplicates,
        'duplicate_capture_sha256s': duplicate_hashes,
        'countable_independent_sessions_by_role': counts,
        'minimum_independent_sessions_per_class': minimum,
        'sessions': results,
        'no_scores_computed': True,
    }

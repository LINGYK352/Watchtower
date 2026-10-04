"""Guardian and contiguous release policy. No framework, mutable globals or IO."""
import re

GUARDIAN = 'v1.21.171'
PACKAGE_START = 'v1.21.172'


def key(version):
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?', version or '')
    if not match:raise ValueError('Invalid update version')
    return tuple(map(int, match.groups()[:3])) + ((0, int(match[4])) if match[4] else (1, 0))


def adjacent(before, after):
    left, right = key(before), key(after)
    if right <= left:return False
    if left[:3] == right[:3]:
        return left[3] == 0 and (right[3] == 1 or right[4] == left[4] + 1)
    return left[:2] == right[:2] and right[2] == left[2] + 1


def build(current, latest, releases, target='', guardian=GUARDIAN):
    """Only the below-guardian bootstrap may cross historical version numbers."""
    key(latest); key(guardian)
    if current:key(current)
    destination = target or latest
    if target and key(destination) > key(latest):raise ValueError('Target is not a released version')
    if not target and current and key(current)>key(latest):destination=current
    records = {r['version']: r for r in releases}
    if len(records) != len(releases):raise ValueError('Duplicate release version')
    direction='rollback' if current and key(destination)<key(current) else 'repair' if destination==current else 'upgrade'
    active = key(latest) >= key(guardian)
    # The guardian owns continuation. Until an independent legacy guardian is
    # installed, rolling it out of the product cannot be a supported chain.
    if active and direction=='rollback' and key(destination)<key(guardian):
        raise ValueError('Rollback before guardian requires an independent update guardian; it is not enabled')
    if active and guardian not in records:raise ValueError('Guardian release is missing; refusing latest fallback')
    if current and (destination==current or not target and key(destination)<key(current)):
        steps = []
    elif not active:
        steps = [destination]
    elif direction=='rollback':
        steps=[];cursor=current;seen=set()
        while cursor!=destination:
            if cursor in seen or cursor not in records:raise ValueError('Rollback chain is missing or cyclic')
            seen.add(cursor);previous=records[cursor].get('prev','')
            if not previous or previous not in records or not adjacent(previous,cursor):raise ValueError('Rollback predecessor is missing or skips a version')
            if any(key(previous)<key(v)<key(cursor) and key(v)>=key(guardian) for v in records):raise ValueError('Rollback skips an available release')
            if key(previous)<key(destination):raise ValueError('Rollback target is outside the released chain')
            steps.append(previous);cursor=previous
    else:
        first = guardian if not current or key(current) < key(guardian) else current
        if key(destination) < key(first):raise ValueError('Requested upgrade bypasses guardian')
        reverse, cursor, seen = [], destination, set()
        while cursor != first:
            if cursor in seen or cursor not in records:raise ValueError('Release chain is missing or cyclic')
            seen.add(cursor); reverse.append(cursor)
            previous = records[cursor].get('prev', '')
            if not previous or not adjacent(previous, cursor):raise ValueError('Release predecessor is missing or skips a version')
            if any(key(previous)<key(v)<key(cursor) and key(v)>=key(guardian) for v in records):raise ValueError('Upgrade skips an available release')
            cursor = previous
            if key(cursor) < key(first):raise ValueError('Current version is outside the released chain')
        steps = ([guardian] if first != current else []) + list(reversed(reverse))
    return {'schema': 1, 'policy': 'mandatory-chain', 'direction':direction,'current': current, 'latest': latest,
            'target': destination, 'guardian': guardian, 'guardian_active': active,
            'minimum_rollback':guardian if active else '',
            'steps': steps, 'next': steps[0] if steps else current or latest,
            'package_start': PACKAGE_START, 'bootstrap_only': not current or key(current) < key(guardian)}


def allow(current, requested, plan):
    key(requested)
    if current and requested==current:return  # same-version repair has no hop
    if requested != plan['next']:raise ValueError('Version skipping is forbidden; update to '+plan['next']+' first')


def transport(version):
    return 'packages' if key(version)[:3] >= key(PACKAGE_START)[:3] else 'files'

def uses_packages(current,target):
    return transport(target)=='packages' or bool(current) and transport(current)=='packages'

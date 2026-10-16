"""Conservative group task targets: never execute an excluded overlapping range."""
import ipaddress
import re


def parts(value):
    if isinstance(value, list):
        return list(dict.fromkeys(str(v).strip() for v in value if str(v).strip()))
    return list(dict.fromkeys(v for v in re.split(r'[,;\s]+', str(value or '').strip()) if v))


def ip_interval(value):
    try:
        if '-' in value:
            start, end = (ipaddress.ip_address(v.strip()) for v in value.split('-', 1))
            if start.version != end.version or int(start) > int(end):
                return None
            return start.version, int(start), int(end)
        network = ipaddress.ip_network(value, strict=False)
        return network.version, int(network.network_address), int(network.broadcast_address)
    except ValueError:
        return None


def overlaps(left, right):
    a, b = ip_interval(left), ip_interval(right)
    if a or b:
        return bool(a and b and a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2])
    a, b = left.lower().rstrip('.'), right.lower().rstrip('.')
    return a == b or a.endswith('.' + b) or b.endswith('.' + a)


def prepare(group):
    # A parent domain/CIDR containing exclusions is omitted as a whole. The
    # current task scanner cannot guarantee a new partial exclusion semantics.
    targets = parts(group.get('scope_array') or group.get('scope'))
    excluded = parts(group.get('black_scope_array') or group.get('black_scope'))
    skipped = [target for target in targets if any(overlaps(target, b) for b in excluded)]
    kept = [target for target in targets if target not in skipped]
    return {'scope_id': str(group.get('_id', '')), 'name': group.get('name', ''),
            'scope': '\n'.join(kept), 'black_scope': '\n'.join(excluded), 'skipped': skipped}

"""Signed two-ZIP transport. Extraction never writes into a live installation."""
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlencode, urlsplit
import base64
import hashlib
import json
import os
import re
import stat
import time
import urllib.error
import zipfile

PUBLIC_KEY = 'REbZ+VtgBKKmbIwUb6vnIaYWOe8LecIKpUxUKV/qW00='
MAX_BYTES = 8 * 1024**3
MAX_MEMBERS = 20000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def safe_path(value):
    if (not isinstance(value, str) or not value or value.startswith('/') or '\\' in value
            or ':' in value or any(ord(c) < 32 for c in value) or len(value.encode('utf-8')) > 1024):
        raise ValueError('Unsafe update path')
    parts = value.split('/')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *[f'COM{i}' for i in range(1, 10)], *[f'LPT{i}' for i in range(1, 10)]}
    if len(parts) > 24 or any(p in ('', '.', '..') or p.endswith((' ', '.')) or p.split('.')[0].upper() in reserved for p in parts):
        raise ValueError('Unsafe update path component')
    return value


def inside(root, name):
    root = Path(root).absolute()
    path = root / safe_path(name)
    path.resolve().relative_to(root.resolve())
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink() or parent.exists() and getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Update path traverses a link')
    return path


class OriginRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, url):
        if (urlsplit(url).scheme, urlsplit(url).netloc) != (urlsplit(req.full_url).scheme, urlsplit(req.full_url).netloc):
            raise ValueError('Authenticated update redirect changes origin')
        return super().redirect_request(req, fp, code, msg, headers, url)


OPENER = build_opener(OriginRedirect())


def verify(plan, product, target, base, validate_name):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    descriptor = plan['descriptor']
    Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(
        base64.b64decode(plan['signature'], validate=True), canonical(descriptor))
    abi = 'windows-amd64-py311-v1' if product == 'windows-amd64' else 'web-source-v2'
    if (descriptor.get('schema') != 1 or descriptor.get('product') != product
            or descriptor.get('runtime_abi') != abi or descriptor.get('version') != target
            or descriptor.get('mode') not in ('full', 'delta')):
        raise ValueError('Update plan product, version or ABI mismatch')
    if descriptor['mode'] == 'delta' and descriptor.get('base_version') != base:
        raise ValueError('Update plan baseline mismatch')
    files, sizes, removed = descriptor['inventory'], descriptor['inventory_bytes'], descriptor['removed']
    if not files or len(files) > MAX_MEMBERS or len({p.casefold() for p in files}) != len(files) or set(sizes) != set(files):
        raise ValueError('Invalid update inventory')
    def entry(name, digest):
        safe_path(name)
        validate_name(name, digest)
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid update digest')
    for name, digest in files.items():
        entry(name, digest)
        if type(sizes[name]) is not int or not 0 <= sizes[name] <= 2 * 1024**3:
            raise ValueError('Invalid update member size')
    for name, digest in removed.items():
        entry(name, digest)
        if name in files:
            raise ValueError('Update deletion overlaps target')
    packages = descriptor['packages']
    if len(packages) != 2 or [p['kind'] for p in packages] != ['common', 'platform']:
        raise ValueError('An update requires exactly common and platform ZIPs')
    seen = set()
    expanded = 0
    for package in packages:
        safe_path(package['resource'])
        prefix = 'common/' if package['kind'] == 'common' else product + '/'
        if not package['resource'].startswith(prefix) or not package['resource'].endswith('.zip'):
            raise ValueError('Cross-platform update package')
        if type(package['bytes']) is not int or not 0 < package['bytes'] <= MAX_BYTES or not re.fullmatch('[0-9a-f]{64}', package['sha256']):
            raise ValueError('Invalid ZIP descriptor')
        for member, metadata in package['members'].items():
            safe_path(member)
            name = 'app/' + member if product == 'windows-amd64' and package['kind'] == 'common' else member
            if name.casefold() in seen or files.get(name) != metadata['sha256'] or sizes.get(name) != metadata['bytes']:
                raise ValueError('ZIP member overlaps or differs from inventory')
            if metadata.get('mode',0o644) not in (0o644,0o755):raise ValueError('Unsafe update permissions')
            if package['kind'] == 'common' and not member.startswith(('sentinel_platform/', 'docker/frontend/', 'dicts/')):
                raise ValueError('Nonportable common resource')
            seen.add(name.casefold())
            expanded += metadata['bytes']
    if len(seen) > MAX_MEMBERS or expanded > MAX_BYTES:
        raise ValueError('Expanded update exceeds budget')
    if descriptor['mode'] == 'full' and seen != {n.casefold() for n in files}:
        raise ValueError('Full package set is incomplete')
    return descriptor


def fetch_plan(source, headers, product, target, base, validate_name, full=False):
    url = source.rstrip('/') + '/packages/plan?' + urlencode({'version': target, 'base': base, 'full': '1' if full else '0'})
    try:
        with OPENER.open(Request(url, headers=headers), timeout=30) as response:
            data = response.read(8 * 1024**2 + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 501):
            return None  # Legacy server/target: one compatibility transition.
        raise
    if len(data) > 8 * 1024**2:
        raise ValueError('Update plan exceeds budget')
    return verify(json.loads(data), product, target, base, validate_name)


def download(url, headers, cache, package, progress=None):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = inside(cache, package['sha256'] + '.zip')
    partial = inside(cache, package['sha256'] + '.part')
    size = package['bytes']
    if target.is_file() and target.stat().st_size == size and sha256(target) == package['sha256']:
        return target
    for attempt in range(3):
        offset = partial.stat().st_size if partial.exists() else 0
        if offset >= size:
            if offset == size and sha256(partial) == package['sha256']:
                os.replace(partial, target)
                return target
            partial.unlink()
            offset = 0
        request_headers = dict(headers, **{'Accept-Encoding': 'identity'})
        if offset:
            request_headers['Range'] = f'bytes={offset}-'
        try:
            with OPENER.open(Request(url, headers=request_headers), timeout=60) as response:
                if response.status == 206:
                    match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                    if not match or int(match[1]) != offset or int(match[2]) != size - 1 or int(match[3]) != size:
                        raise ValueError('ZIP resume range differs from signed size')
                    mode = 'ab'
                elif response.status == 200:
                    mode, offset = 'wb', 0
                else:
                    raise ValueError('Unexpected ZIP response')
                with partial.open(mode) as output:
                    while True:
                        block = response.read(min(1024 * 1024, size - offset + 1))
                        if not block:
                            break
                        offset += len(block)
                        if offset > size:
                            raise ValueError('ZIP exceeds signed size')
                        output.write(block)
                        if progress:
                            progress(offset, size)
                    output.flush()
                    os.fsync(output.fileno())
            if offset != size:
                raise ConnectionError('Interrupted ZIP download')
        except (OSError, ConnectionError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 401, 403, 404, 416):
                raise
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
            continue
        if sha256(partial) != package['sha256']:
            partial.unlink()
            raise ValueError('ZIP digest mismatch; live installation unchanged')
        os.replace(partial, target)
        return target
    raise ConnectionError('ZIP download failed')


def stage(descriptor, source, headers, cache, destination, wanted, progress=None):
    """Authenticate/download BOTH archives before extraction. Return staged paths."""
    resources = []
    for package in descriptor['packages']:
        query = {'version': descriptor['version'], 'base': headers.get('X-Client-Version', descriptor['base_version']),
                 'full': '1' if descriptor['mode'] == 'full' else '0', 'resource': package['resource']}
        url = source.rstrip('/') + '/packages/download?' + urlencode(query)
        resources.append(download(url, headers, cache, package, progress))
    staged = {}
    for package, blob in zip(descriptor['packages'], resources):
        with zipfile.ZipFile(blob) as archive:
            infos = archive.infolist()
            if len(infos) != len(package['members']) or len({i.filename.casefold() for i in infos}) != len(infos):
                raise ValueError('ZIP duplicate or missing members')
            for info in infos:
                safe_path(info.filename)
                mode = info.external_attr >> 16
                item = package['members'].get(info.filename)
                if not item or info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or info.flag_bits & 1 or info.compress_type != zipfile.ZIP_DEFLATED:
                    raise ValueError('ZIP unregistered member, link or unsupported encoding')
                if info.file_size != item['bytes'] or info.file_size > max(1, info.compress_size) * 10000:
                    raise ValueError('ZIP size/expansion mismatch')
                name = 'app/' + info.filename if descriptor['product'] == 'windows-amd64' and package['kind'] == 'common' else info.filename
                if name not in wanted:
                    continue
                output = inside(destination, name)
                output.parent.mkdir(parents=True, exist_ok=True)
                count, digest = 0, hashlib.sha256()
                with archive.open(info) as input_file, output.open('wb') as out:
                    for block in iter(lambda: input_file.read(1024 * 1024), b''):
                        count += len(block)
                        if count > item['bytes']:
                            raise ValueError('Expanded member exceeds signed size')
                        out.write(block)
                        digest.update(block)
                if count != item['bytes'] or digest.hexdigest() != item['sha256']:
                    raise ValueError('Extracted member mismatch')
                if os.name!='nt':os.chmod(output,item.get('mode',0o644))
                staged[name] = str(output)
    if set(staged) != set(wanted):
        raise ValueError('Two-package set does not cover required changes')
    return staged

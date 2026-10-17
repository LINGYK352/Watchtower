"""Same-origin native UI files; business API requests stay on the HTTP service."""
from pathlib import Path
from urllib.parse import unquote
import hashlib, json

REVISION = '20261017-r8'
MAX_ASSET_BYTES = 32 * 1024 * 1024
TYPES = {'.js':'text/javascript', '.mjs':'text/javascript', '.css':'text/css',
         '.html':'text/html', '.json':'application/json', '.map':'application/json',
         '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon',
         '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif',
         '.webp':'image/webp', '.avif':'image/avif', '.woff':'font/woff',
         '.woff2':'font/woff2', '.ttf':'font/ttf', '.otf':'font/otf',
         '.wasm':'application/wasm', '.webmanifest':'application/manifest+json',
         '.txt':'text/plain', '.xml':'application/xml'}

class Bundle:
    def __init__(self, root):
        self.last_failure = None
        self.root = Path(root).resolve()
        self.folder = (self.root / 'app/docker/frontend').resolve()
        self.folder.relative_to(self.root)
        receipt = json.loads((self.root / 'state/native-release-receipt.json').read_text(encoding='utf-8'))
        self.files = receipt['files']
        if not isinstance(self.files, dict) or len(self.files) > 20000:
            raise ValueError('Invalid UI installation receipt')
        self.version = receipt['version']

    def identity(self):
        relative = 'app/docker/frontend/index.html'
        content = (self.root / relative).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        import re
        entry = re.search(r'type="module"[^>]*src="([^"]+)"', content.decode('utf-8'))
        return {'gui_revision': REVISION, 'version': self.version,
                'index_sha256': digest, 'index_matches_receipt': digest == self.files.get(relative),
                'main_entry': entry.group(1) if entry else '', 'transport': 'native-verified-file'}

    def respond(self, path, method='GET'):
        self.last_failure = None
        if method not in ('GET', 'HEAD'):
            return None
        relative = unquote(path).lstrip('/')
        if relative.startswith(('api/', '__native')):
            return None
        def response(status, kind, data, reason):
            headers = {'Content-Type': kind, 'Content-Length': str(len(data)),
                       'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                       'X-Watchtower-Resource-Status': reason,
                       'X-Watchtower-Resource-Source': 'native-verified-file'}
            return status, headers, b'' if method == 'HEAD' else data
        def error(status, reason):
            self.last_failure = {'path': '/'+relative[:160], 'status': status, 'reason': reason}
            if reason == 'missing':self.last_failure['exists'] = False
            elif reason in ('integrity_mismatch','not_in_installation_receipt','asset_too_large'):self.last_failure['exists'] = True
            return response(status, 'text/plain; charset=utf-8', ('UI resource '+reason+': '+relative[:200]).encode('utf-8'), reason)
        if path.startswith('//') or '\\' in relative or ':' in relative or '..' in relative.split('/') or any(ord(c)<32 for c in relative):
            return error(404, 'invalid_path')
        try:
            candidate = (self.folder / relative).resolve()
            candidate.relative_to(self.folder)
            if not candidate.is_file():
                if relative.startswith('assets/') or candidate.suffix.lower() in TYPES:
                    return error(404, 'missing')
                candidate = (self.folder / 'index.html').resolve()
                candidate.relative_to(self.folder)
            name = candidate.relative_to(self.root).as_posix()
            expected = self.files.get(name)
            if expected is None:
                return error(409, 'not_in_installation_receipt')
            if candidate.stat().st_size > MAX_ASSET_BYTES:
                return error(413, 'asset_too_large')
            with candidate.open('rb') as stream:
                data = stream.read(MAX_ASSET_BYTES + 1)
            if len(data) > MAX_ASSET_BYTES:
                return error(413, 'asset_too_large')
            if hashlib.sha256(data).hexdigest() != expected:
                result = error(409, 'integrity_mismatch')
                self.last_failure.update(exists=True, bytes=len(data), expected_sha256=expected, actual_sha256=hashlib.sha256(data).hexdigest())
                return result
            kind = TYPES.get(candidate.suffix.lower(), 'application/octet-stream')
            if kind.startswith('text/') or kind == 'image/svg+xml':
                kind += '; charset=utf-8'
            return response(200, kind, data, 'ok')
        except (OSError, ValueError) as exc:
            result = error(503, 'unreadable')
            self.last_failure.update(exception=type(exc).__name__, errno=getattr(exc,'errno',None), winerror=getattr(exc,'winerror',None))
            return result

"""Native UI resources are a protocol, independent of Windows file associations."""
from pathlib import Path
import os

MIME_TYPES = {
    '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
    '.html': 'text/html', '.json': 'application/json', '.map': 'application/json',
    '.wasm': 'application/wasm', '.webmanifest': 'application/manifest+json',
    '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
    '.webp': 'image/webp', '.avif': 'image/avif', '.woff': 'font/woff',
    '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf',
    '.txt': 'text/plain', '.xml': 'application/xml',
}


def install(app, *, root=None):
    """Adapt the existing frozen service's frontend view through delivered code.

    API/control endpoints keep their existing routing and authentication. A
    missing asset is never a successful HTML response. No registry is changed.
    """
    if root is None:
        if os.environ.get('WATCHTOWER_NATIVE_PREVIEW') != '1':
            return False
        root = os.environ.get('SENTINEL_NATIVE_ROOT')
        if not root:
            return False
    if app.extensions.get('watchtower.native_frontend'):
        return True
    folder = (Path(root).resolve() / 'app/docker/frontend').resolve()
    from flask import request, Response, send_file

    def error(relative, status, reason):
        response = Response('UI resource ' + reason + ': ' + relative[:240],
                            status=status, mimetype='text/plain')
        response.headers['X-Watchtower-Resource-Status'] = reason
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    def serve():
        # The frozen backend registers this view after create_app returns.
        if request.endpoint != 'frontend' or request.method not in ('GET', 'HEAD'):
            return None
        relative = (request.view_args or {}).get('path', '')
        if relative.startswith(('api/', '__native')):
            return None
        # Reject Windows drives, ADS and UNC separators before resolving paths.
        if '\\' in relative or ':' in relative or relative.startswith('/') or '..' in relative.split('/') or any(ord(char) < 32 for char in relative):
            return error('invalid path', 404, 'missing')
        try:
            candidate = (folder / relative).resolve()
            candidate.relative_to(folder)
            exists = candidate.is_file()
        except (ValueError, OSError):
            return error('invalid path', 404, 'missing')
        suffix = candidate.suffix.lower()
        if not exists:
            if relative.startswith('assets/') or suffix in MIME_TYPES:
                return error(relative, 404, 'missing')
            candidate = (folder / 'index.html').resolve()
            try:
                candidate.relative_to(folder)
                if not candidate.is_file():
                    return error('index.html', 503, 'bundle_missing')
            except (ValueError, OSError):
                return error('index.html', 503, 'bundle_missing')
            suffix = '.html'
        try:
            # Explicit types bypass mimetypes' Windows registry database.
            # An unconditional response replaces stale MIME headers in caches.
            response = send_file(candidate, mimetype=MIME_TYPES.get(suffix, 'application/octet-stream'),
                                 conditional=False, max_age=0)
        except FileNotFoundError:
            return error(relative, 404, 'missing')
        except OSError:
            return error(relative, 503, 'unreadable')
        response.headers['Cache-Control'] = 'no-store' if suffix == '.html' else 'no-cache, max-age=0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Watchtower-Resource-Status'] = 'ok'
        return response

    app.before_request(serve)
    app.extensions['watchtower.native_frontend'] = True
    return True

"""Explicit product identity for activation auditing; OS alone cannot identify a Web deployment."""
from pathlib import Path
from .paths import project_root
from .update_platform import request_headers


def metadata(product):
    if product not in ('web', 'win'):
        raise ValueError('Unknown activation product')
    try:
        version = (Path(project_root()) / 'version.txt').read_text(encoding='utf-8').strip()
    except OSError:
        version = ''
    body = {'client_type': product, 'client_version': version}
    headers = request_headers('web' if product == 'web' else 'windows-native', 'web-source-v2' if product == 'web' else 'windows-amd64-py311-v1')
    if version:
        headers['X-Client-Version'] = version
    return body, headers

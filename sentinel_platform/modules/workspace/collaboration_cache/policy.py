"""File-level limits and independently bounded package/cache policies."""
import hashlib
import io
import json
import re
import stat
import zipfile
import os
from pathlib import Path
from pathlib import PurePosixPath

MIB = 1024 * 1024
MAX_FILE = 20 * MIB
MAX_PACKAGE = 64 * MIB
CHUNK = 2 * MIB
MAX_EXPANDED = 256 * MIB
MAX_FILES = 10000


class CacheError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CacheError(name + '超出允许范围 / Outside allowed range')
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value):
        raise CacheError('对象标识无效 / Invalid object identifier')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def managed_path(value):
    value = os.path.abspath(str(value))
    if os.name == 'nt' and not value.startswith('\\\\?\\'):
        value = '\\\\?\\UNC\\' + value[2:] if value.startswith('\\\\') else '\\\\?\\' + value
    return Path(value)


DEFAULT = {'mode': 'realtime', 'node_id': '', 'pending_days': 7, 'received_hours': 24,
           'shared_days': 30, 'group_quota': 512 * MIB, 'sender_quota': 128 * MIB}


def normalize(body=None, current=None):
    if body is not None and not isinstance(body, dict):
        raise CacheError('缓存策略须为对象 / Cache policy must be an object')
    result = dict(DEFAULT)
    result.update(current or {})
    result.update(body or {})
    if result['mode'] not in ('realtime', 'hosted'):
        raise CacheError('缓存模式无效 / Invalid cache mode')
    node = result.get('node_id') or ''
    if node:
        identifier(node)
    result['node_id'] = node
    for field in ('pending_days', 'shared_days'):
        integer(result[field], field, 1, 90)
    integer(result['received_hours'], 'received_hours', 1, 168)
    integer(result['group_quota'], 'group_quota', MAX_PACKAGE, 64 * 1024 * MIB)
    integer(result['sender_quota'], 'sender_quota', MAX_PACKAGE, result['group_quota'])
    return {field: result[field] for field in DEFAULT}


def safe_name(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise CacheError('文件路径无效 / Invalid file path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') or ':' in part for part in value.split('/')):
        raise CacheError('文件路径越界 / File path outside package')
    return value


def archive_manifest(raw):
    """Verify actual expanded member sizes; compression cannot bypass MAX_FILE."""
    if not isinstance(raw, bytes) or len(raw) > MAX_PACKAGE:
        raise CacheError('共享包超过64MiB / Share package exceeds 64MiB', 413)
    files, seen, total = [], set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise CacheError('共享文件数量过多 / Too many shared files', 413)
            for info in infos:
                name = info.filename.rstrip('/') if info.is_dir() else info.filename
                safe_name(name)
                normalized = name.casefold()
                if normalized in seen:
                    raise CacheError('共享包含重复路径 / Duplicate package paths')
                seen.add(normalized)
                mode = info.external_attr >> 16
                if info.flag_bits & 1 or stat.S_ISLNK(mode):
                    raise CacheError('共享包不允许加密ZIP或符号链接 / Encrypted ZIPs and symlinks are unsupported')
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE:
                    raise CacheError('单个文件不能超过20MiB：' + name + ' / File exceeds 20MiB', 413)
                size, checksum = 0, hashlib.sha256()
                with archive.open(info) as member:
                    while True:
                        block = member.read(min(256 * 1024, MAX_FILE - size + 1))
                        if not block:
                            break
                        size += len(block)
                        if size > MAX_FILE:
                            raise CacheError('单个文件不能超过20MiB：' + name + ' / File exceeds 20MiB', 413)
                        checksum.update(block)
                total += size
                if total > MAX_EXPANDED:
                    raise CacheError('共享包展开总量超限 / Expanded package total exceeded', 413)
                files.append({'path': name, 'size': size, 'sha256': checksum.hexdigest()})
    except CacheError:
        raise
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        raise CacheError('共享包无效或损坏 / Invalid or damaged share package') from None
    return {'files': files, 'bytes': len(raw), 'expanded_bytes': total,
            'sha256': hashlib.sha256(raw).hexdigest()}

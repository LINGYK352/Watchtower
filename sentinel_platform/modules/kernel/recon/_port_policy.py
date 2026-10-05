"""Translate persisted UI port choices without silently expanding their scope."""
import re

def ranges(value):
    if not isinstance(value,str) or not value.strip():raise ValueError('Port range is empty')
    result=[]
    for part in value.split(','):
        match=re.fullmatch(r'\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s*',part)
        if not match:raise ValueError('Invalid port range')
        left=int(match[1]);right=int(match[2]) if match[2] else left
        if not 0<=left<=right<=65535:raise ValueError('Port is outside the network port range')
        name=str(left)+('-'+str(right) if match[2] else '')
        if name not in result:result.append(name)
    return ','.join(result)

def select(options):
    explicit=options.get('ports')
    if explicit is not None:
        if explicit in ('top-100','top-1000','full'):return explicit
        return ranges(explicit)
    mode=str(options.get('port_scan_type') or 'top1000').strip().lower()
    if mode=='none':return ''
    if mode in ('custom','test'):return ranges(options.get('port_custom','80,443') if mode=='test' else options.get('port_custom',''))
    aliases={'all':'full','full':'full','top100':'top-100','top-100':'top-100','top1000':'top-1000','top-1000':'top-1000','100':'top-100','1000':'top-1000'}
    if mode not in aliases:raise ValueError('Unsupported port scan choice')
    return aliases[mode]

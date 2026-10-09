"""Probe the actual writable data volume; absolute headroom drives admission."""
from pathlib import Path
import os,math

def data_disk_path():
    native=os.environ.get('SENTINEL_NATIVE_ROOT','')
    if native:path=Path(native)/'state'
    elif os.environ.get('SENTINEL_WORKSPACE'):path=Path(os.environ['SENTINEL_WORKSPACE'])
    else:
        from .paths import project_root
        path=Path(project_root())/'shared'
    while not path.is_dir() and path!=path.parent:path=path.parent
    return str(path.resolve())

def snapshot():
    import psutil
    path=data_disk_path();disk=psutil.disk_usage(path)
    return {'path':path,'total':disk.total,'used':disk.used,'free':disk.free,'percent':disk.percent}

def thresholds():
    defaults=[1.5,3.0,8.0,20.0];keys=['DISK_FREE_CRIT_GB','DISK_FREE_TIGHT_GB','DISK_FREE_GOOD_GB','DISK_FREE_EXCELLENT_GB'];values=[]
    for key,default in zip(keys,defaults):
        try:
            from .config import get_config
            value=float(get_config().section('RESOURCE',key,default=default))
            if not math.isfinite(value) or value<=0:raise ValueError()
        except Exception:value=default
        values.append(value)
    return tuple(values if all(a<b for a,b in zip(values,values[1:])) else defaults)

def level(info):
    if not info or info.get('free') is None:return 'relaxed'
    free=float(info['free'])/1024**3;critical,tight,good,excellent=thresholds()
    if free<=critical:return 'critical'
    if free<=tight:return 'tight'
    return 'relaxed'

"""Optional deployment properties; the same updater serves Web and managed runtimes."""
from contextlib import contextmanager
from pathlib import Path
import ast,hashlib,json,os
import yaml

CONTRACT=1
PROFILE='.deployment-profile.json'
STATE='.deployment-state'
UPDATER='sentinel_platform/modules/about/_updater.py'
SELF='sentinel_platform/core/deployment_profile.py'


def load(root):
    p=Path(root)/PROFILE
    if not p.is_file():
        if os.environ.get('WATCHTOWER_MANAGED_RUNTIME')=='1' or (Path(root)/STATE/'managed.json').exists():raise ValueError('受管理运行环境的部署配置缺失，拒绝更新')
        return None
    data=json.loads(p.read_text(encoding='utf-8'))
    if data.get('schema')!=1 or data.get('contract')!=CONTRACT or not isinstance(data.get('runtime_abi'),str):raise ValueError('部署配置契约无效')
    return data


@contextmanager
def transaction(root):
    # The lock lives on shared storage, not in one Flask worker's memory.
    state=Path(root)/STATE;state.mkdir(exist_ok=True)
    with (state/'update.lock').open('a+b') as f:
        f.write(b'0');f.flush();f.seek(0)
        try:
            if os.name=='nt':
                import msvcrt;msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl;fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as exc:raise RuntimeError('已有核心更新正在执行') from exc
        try:yield
        finally:
            f.seek(0)
            if os.name=='nt':msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(f,fcntl.LOCK_UN)


def validate(root,data):
    profile=load(root)
    if not profile:return
    if data.get('deployment_contract')!=CONTRACT or data.get('runtime_abi')!=profile['runtime_abi']:raise ValueError('更新缺少兼容部署契约或要求不同运行环境；请先更新配套运行组件')
    manifest=data.get('manifest',{})
    if SELF not in manifest or UPDATER not in manifest:raise ValueError('核心分发包缺少共用部署兼容接口')


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def source_hash(root,rel,actual):
    if not load(root):return actual
    path=Path(root)/STATE/'overlays.json'
    try:receipt=json.loads(path.read_text(encoding='utf-8')).get(rel,{})
    except (OSError,ValueError):return actual
    return receipt.get('upstream',actual) if receipt.get('effective')==actual else actual


def _get(data,path):
    for item in path:
        if not isinstance(data,dict) or item not in data:return None
        data=data[item]
    return data


def _set(data,path,value):
    current=data
    for item in path[:-1]:current=current.setdefault(item,{})
    current[path[-1]]=value


def prepare(root,staged,manifest):
    profile=load(root)
    if not profile:return list(staged)
    root=Path(root);state=root/STATE;state.mkdir(exist_ok=True)
    receipt_path=state/'overlays.json'
    try:receipts=json.loads(receipt_path.read_text(encoding='utf-8'))
    except (OSError,ValueError):receipts={}
    result=[]
    for rel,file in staged:
        file=Path(file)
        if rel==UPDATER:
            tree=ast.parse(file.read_text(encoding='utf-8'))
            contract=any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEPLOYMENT_UPDATE_CONTRACT' for t in n.targets) and isinstance(n.value,ast.Constant) and n.value.value==CONTRACT for n in tree.body)
            if not contract:raise ValueError('目标核心更新器不支持共用部署契约，拒绝替换')
        if rel=='docker/docker-compose.yml':
            incoming=yaml.safe_load(file.read_text(encoding='utf-8'));existing=yaml.safe_load((root/rel).read_text(encoding='utf-8'))
            if not isinstance(incoming,dict) or not isinstance(incoming.get('services'),dict):raise ValueError('容器配置无效')
            for path in profile.get('preserve_compose_paths',[]):
                if not isinstance(path,list) or not path or not all(isinstance(x,str) for x in path):raise ValueError('部署保留路径无效')
                if len(path)>=2 and path[0]=='services' and path[1] not in incoming['services'] and path[1] in existing.get('services',{}):raise ValueError('更新移除了受管理服务，需配套部署迁移')
                value=_get(existing,path)
                if value is not None:_set(incoming,path,value)
            if incoming==existing:
                receipts[rel]={'upstream':manifest[rel],'effective':digest(root/rel)}
                continue
            encoded=yaml.safe_dump(incoming,allow_unicode=True,sort_keys=False)
            file.write_text(encoded,encoding='utf-8')
            effective=digest(file)
            receipts[rel]={'upstream':manifest[rel],'effective':effective}
            # Same effective configuration needs no replacement or container recreation.
            if (root/rel).is_file() and digest(root/rel)==effective:continue
        result.append((rel,str(file)))
    pending=receipt_path.with_suffix('.pending');pending.write_text(json.dumps(receipts));os.replace(pending,receipt_path)
    return result

"""Public signed desktop channel; core business updates use the shared Web updater."""
from pathlib import Path
import base64,json,re
from windows_preview.desktop_update import active,PRODUCT
from windows_preview._trust import PUBLIC_KEY
from windows_preview.signed_download import signed_manifest,asset_source,download

CHANNEL_PRODUCT=PRODUCT+'-channel'


def version_key(value):
    m=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?-build(\d+)',value)
    if not m:raise ValueError('Windows 版本无效')
    return tuple(map(int,m.groups()[:3]))+(1 if m[4] is None else 0,int(m[4] or 0),int(m[5]))


def check(root):
    root=Path(root);config_path=root/'update-channel.json'
    if not config_path.is_file():return None
    config=json.loads(config_path.read_text(encoding='utf-8'))
    source=config.get('source','')
    if not source:return None
    manifest=signed_manifest(source,base64.b64decode(PUBLIC_KEY),CHANNEL_PRODUCT,'channel.json')
    if manifest.get('channel')!=config.get('channel','testing'):raise ValueError('更新渠道不匹配')
    current=active(root)['version']
    offers=[r for r in manifest.get('releases',[]) if r.get('base')==current and version_key(r['target'])>version_key(current)]
    if not offers:return {'current':current,'available':False}
    offer=max(offers,key=lambda r:version_key(r['target']))
    if offer.get('runtime_abi','linux-amd64-py311-v1')!='linux-amd64-py311-v1':raise ValueError('此更新要求不同运行环境，请使用配套安装包')
    return {'current':current,'available':True,'release':offer,'source':source}


def fetch(root,offer,progress=None,cancel=None):
    if active(root)['version']!=offer['current']:raise ValueError('程序版本已改变，请重新检查更新')
    r=offer['release']
    return download(asset_source(offer['source'],r['file']),Path(root)/'state/downloads',r['sha256'],r['bytes'],progress,cancel)

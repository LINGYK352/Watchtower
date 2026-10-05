"""Native startup screen, with bundled artwork and independent locale assets."""
from pathlib import Path
import base64,html,json
ASSETS=Path(__file__).with_name('assets')

def locale(root):
    try:value=json.loads((Path(root)/'state/ui-language.json').read_text(encoding='utf-8'))['locale']
    except (OSError,ValueError,KeyError):value='zh-CN'
    return value if value in ('zh-CN','en-US') else 'zh-CN'

def messages(root):
    return json.loads((ASSETS/'locales'/(locale(root)+'.json')).read_text(encoding='utf-8'))

class Api:
    def __init__(self,root):self.root=Path(root)
    def get_locale(self):return locale(self.root)
    def set_locale(self,value):
        if value not in ('zh-CN','en-US'):raise ValueError('Unsupported language')
        from windows_native.update_state import write
        write(self.root/'state/ui-language.json',{'locale':value})
        return {'ok':True}

def render(root,failed=False):
    text=messages(root)['startup'];version=(Path(root)/'app/version.txt').read_text(encoding='utf-8').strip()
    image=base64.b64encode((ASSETS/'watchtower.png').read_bytes()).decode()
    status=text['failed'] if failed else text['checking']
    hint=text['failureHint'] if failed else text['firstRunHint'] if not (Path(root)/'state/db-initialized.json').exists() else text['readyHint']
    page='''<!doctype html><html lang="__LANG__"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box}html,body{height:100%;margin:0}body{overflow:hidden;background:#0c1422;color:#edf4ff;font-family:"Segoe UI","Microsoft YaHei",sans-serif}
.backdrop{position:fixed;inset:0;background:radial-gradient(ellipse 550px 470px at 50% 47%,#142b46 0%,#0f1f34 40%,#0b1321 100%)}
.content{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px;transform:translateY(15px)}
.logo{width:98px;height:98px;object-fit:contain;filter:drop-shadow(0 12px 32px #0003);animation:enter .45s ease-out both}
h1{font-size:44px;line-height:1.1;font-weight:700;letter-spacing:.4px;margin:42px 0 22px;animation:enter .5s .08s ease-out both}
.caption{font-size:18px;color:#6899d1;letter-spacing:4px}.track{height:4px;width:270px;border-radius:3px;background:#1c3550;margin:43px 0 65px;overflow:hidden}
.bar{height:100%;width:4%;background:linear-gradient(90deg,#397acd,#13c6db);border-radius:3px;transition:width .35s ease;position:relative}
.bar:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,#d3faff55,transparent);animation:shine 1.6s linear infinite}
#status{font-size:24px;line-height:1.5;margin:0 0 23px;min-height:36px}.hint{color:#799cc9;font-size:20px;text-align:center;line-height:1.6;margin:0 0 48px}.version{font-size:16px;color:#4f78a8}
@keyframes shine{from{transform:translateX(-100%)}to{transform:translateX(100%)}}@keyframes enter{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:750px){h1{font-size:34px}.hint{font-size:16px}#status{font-size:20px}.logo{width:84px;height:84px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style><body><div class="backdrop"></div><main class="content"><img class="logo" src="data:image/png;base64,__IMAGE__" alt="Watchtower">
<h1>WATCHTOWER</h1><div class="caption">__CAPTION__</div><div class="track" role="progressbar" aria-label="__PROGRESS__" aria-valuemin="0" aria-valuemax="100" aria-valuenow="4"><div class="bar" id="bar"></div></div>
<p id="status" role="status" aria-live="polite">__STATUS__</p><p class="hint">__HINT__</p><div class="version">__VERSION__</div></main>
<script>window.watchtowerStartup=function(message,percent){document.getElementById('status').textContent=message;document.getElementById('bar').style.width=percent+'%';document.querySelector('[role=progressbar]').setAttribute('aria-valuenow',percent)};</script></body></html>'''
    version_text=text['version'] if '-' in version else text.get('stableVersion','{version}')
    values={'LANG':locale(root),'IMAGE':image,'CAPTION':text['caption'],'PROGRESS':text['progress'],'STATUS':status,'HINT':hint,'VERSION':version_text.replace('{version}',version)}
    for key,value in values.items():page=page.replace('__'+key+'__',html.escape(value,quote=True))
    return page

"""Normal text/browser controls without debug menus or developer tools."""
from pathlib import Path
import json

def apply(window,root):
    import System
    try:zoom=float(json.loads((Path(root)/'state/window-preferences.json').read_text()).get('zoom',1.0))
    except (OSError,ValueError,TypeError):zoom=1.0
    zoom=max(.5,min(2.0,zoom))
    def configure():
        view=window.native.browser.webview
        settings=view.CoreWebView2.Settings
        settings.AreDefaultContextMenusEnabled=True
        settings.AreBrowserAcceleratorKeysEnabled=True
        settings.AreDevToolsEnabled=False
        view.ZoomFactor=zoom
        install_downloads(window,view)
    window.native.Invoke(System.Action(configure))


DOWNLOAD_LIFETIME_SCRIPT=r"""(()=>{
 if(window.__watchtowerNativeDownloadDone)return;
 const release=URL.revokeObjectURL.bind(URL),pending=new Set(),requested=new Set(),done=new Set();
 const track=a=>{if(a.download&&a.href.startsWith('blob:'))pending.add(a.href)};
 const click=HTMLAnchorElement.prototype.click;
 HTMLAnchorElement.prototype.click=function(){track(this);return click.call(this)};
 document.addEventListener('click',e=>{const a=e.target.closest?.('a[download]');if(a)track(a)},true);
 URL.revokeObjectURL=url=>{if(pending.has(url)&&!done.has(url))requested.add(url);else release(url)};
 window.__watchtowerNativeDownloadDone=url=>{pending.delete(url);done.add(url);if(requested.delete(url))release(url);if(done.size>128)done.delete(done.values().next().value)};
})()"""

def install_downloads(window,view):
    """The built-in WebView handler always shows SaveFileDialog; this owns URL cleanup."""
    if getattr(window,'_watchtower_download_lifetime',None):return
    core=view.CoreWebView2;operations={}
    core.AddScriptToExecuteOnDocumentCreatedAsync(DOWNLOAD_LIFETIME_SCRIPT)
    core.ExecuteScriptAsync(DOWNLOAD_LIFETIME_SCRIPT)
    def complete(uri):
        try:core.ExecuteScriptAsync('window.__watchtowerNativeDownloadDone?.('+json.dumps(uri)+')')
        except Exception:pass  # A closed document has already released its URLs.
    def starting(sender,args):
        operation=args.DownloadOperation;uri=str(operation.Uri)
        if not uri.startswith('blob:'):return
        # pywebview's first handler has already completed the user's Save As choice.
        if args.Cancel:complete(uri);return
        key=id(operation)
        def changed(sender,event):
            if str(operation.State) not in ('Completed','Interrupted'):return
            complete(uri)
            try:operation.StateChanged-=changed
            finally:operations.pop(key,None)
        operations[key]=(operation,changed);operation.StateChanged+=changed
        changed(operation,None)
    core.DownloadStarting+=starting
    window._watchtower_download_lifetime=(starting,operations)

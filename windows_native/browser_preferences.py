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
    window.native.Invoke(System.Action(configure))

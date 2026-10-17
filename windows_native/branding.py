"""Bundled Watchtower identity for native windows; no Tk default feather icon."""
from pathlib import Path
def assets():return Path(__file__).with_name('assets')
def apply(window):
    try:window.iconbitmap(default=str(assets()/'watchtower.ico'))
    except Exception:
        try:
            import tkinter as tk
            window._watchtower_icon=tk.PhotoImage(file=str(assets()/'watchtower.png'));window.iconphoto(True,window._watchtower_icon)
        except Exception:pass
def palette():
    dark=False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as key:dark=winreg.QueryValueEx(key,'AppsUseLightTheme')[0]==0
    except OSError:pass
    return {'bg':'#0d1727','card':'#152338','text':'#e6eef8','muted':'#93aac4','border':'#2d4058','accent':'#3285ed','soft':'#223e61','danger':'#df626d'} if dark else {'bg':'#edf3fa','card':'#ffffff','text':'#243b53','muted':'#637b94','border':'#d6e1ee','accent':'#176fe8','soft':'#e6f0ff','danger':'#c64958'}

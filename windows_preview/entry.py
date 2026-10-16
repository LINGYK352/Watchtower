"""Small stable entry; updating the desktop app does not overwrite this running file."""
from pathlib import Path
import json,re,subprocess,sys
import tkinter.messagebox

def main():
    root=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]
    try:
        version=json.loads((root/'active.json').read_text(encoding='utf-8'))['version']
        if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-\d+)?-build\d+',version):raise ValueError('版本记录无效')
        app=root/'versions'/version/'WatchtowerDesktop.exe'
        if not app.is_file():raise FileNotFoundError('Windows 程序文件缺失')
        subprocess.Popen([str(app)],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as exc:
        tkinter.messagebox.showerror('Watchtower 测试版',str(exc)+'\n请保留完整测试文件夹。')

if __name__=='__main__':main()

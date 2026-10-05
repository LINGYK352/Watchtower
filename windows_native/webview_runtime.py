"""Detect and automatically install Microsoft's per-user WebView2 runtime."""
from pathlib import Path
import os,subprocess,time

def present():
    if os.name!='nt':return False
    import winreg
    key=r'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    for hive in [winreg.HKEY_CURRENT_USER,winreg.HKEY_LOCAL_MACHINE]:
        for flags in [winreg.KEY_READ|winreg.KEY_WOW64_32KEY,winreg.KEY_READ|winreg.KEY_WOW64_64KEY]:
            try:
                with winreg.OpenKey(hive,key,0,flags) as handle:value=winreg.QueryValueEx(handle,'pv')[0]
                if value and value!='0.0.0.0':return True
            except OSError:pass
    return False

def ensure_webview2(cache,progress):
    if present():progress('已检测到 WebView2');return
    from windows_preview.signed_download import OPENER,validate_url
    import shutil
    target=Path(cache)/'MicrosoftEdgeWebview2Setup.exe'
    progress('正在准备微软 WebView2 运行库')
    with OPENER.open(validate_url('https://go.microsoft.com/fwlink/p/?LinkId=2124703'),timeout=30) as response,target.open('wb') as out:shutil.copyfileobj(response,out)
    literal="'"+str(target).replace("'","''")+"'"
    script='$s=Get-AuthenticodeSignature -LiteralPath '+literal+'; if($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "(?:^|,\\s*)O=Microsoft Corporation(?:,|$)"){exit 1}'
    hidden=getattr(subprocess,'CREATE_NO_WINDOW',0)
    checked=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,creationflags=hidden)
    if checked.returncode:raise ValueError('微软运行库发布者签名检查失败')
    completed=subprocess.run([str(target),'/silent','/install'],timeout=300,creationflags=hidden)
    if completed.returncode:raise RuntimeError('WebView2 安装未完成')
    for _ in range(60):
        if present():return
        time.sleep(1)
    raise RuntimeError('WebView2 安装后检测未通过，请查看运行库安装结果')

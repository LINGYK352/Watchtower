"""Read-only Windows application firewall hint; never changes rules or elevates."""
import os,sys,time,json,threading,subprocess,base64
_lock=threading.Lock();_cached={};_until=0
def status(port):
    global _cached,_until
    if os.name!='nt':return {'state':'not_applicable'}
    with _lock:
        if _until>time.monotonic() and _cached.get('port')==port:return dict(_cached)
        program=sys.executable.replace("'","''")
        script="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;@(Get-NetFirewallApplicationFilter -Program '"+program+"' -ErrorAction Stop | Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block'} | ForEach-Object {$r=$_;$p=$r|Get-NetFirewallPortFilter;[pscustomobject]@{profile=[string]$r.Profile;ports=@($p.LocalPort);protocol=[string]$p.Protocol}})|ConvertTo-Json -Compress"
        result={'state':'unknown','port':port}
        try:
            run=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],capture_output=True,timeout=4,creationflags=subprocess.CREATE_NO_WINDOW)
            if run.returncode==0:
                rows=json.loads(run.stdout.decode('utf-8-sig') or '[]');rows=[rows] if isinstance(rows,dict) else rows
                blocked=[]
                for row in rows:
                    if row.get('protocol','').upper() not in ('TCP','6','ANY','256'):continue
                    for value in row.get('ports') or []:
                        match=value=='Any' or value==str(port)
                        if '-' in value:
                            try:left,right=map(int,value.split('-',1));match=left<=port<=right
                            except ValueError:pass
                        if match:blocked.append(row.get('profile',''));break
                result={'state':'blocked' if blocked else 'not_detected','port':port,'profiles':sorted(set(blocked))}
        except (OSError,ValueError,subprocess.TimeoutExpired):pass
        _cached=result;_until=time.monotonic()+15
        return dict(result)

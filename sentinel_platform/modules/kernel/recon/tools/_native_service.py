"""Bounded native TCP/banner and HTTP/TLS identification; no Nmap data/code."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import re,socket,ssl,time
from ..models import PortInfo
from ..base import ToolCancelled

def detect(host,ports,timeout=30,cancel_check=None):
    if not isinstance(host,str) or not host or len(host)>253 or any(ord(c)<33 or c in '/\\' for c in host):raise ValueError('Invalid service host')
    clean=[]
    for port in ports or []:
        if type(port) is bool or not str(port).isdigit():continue
        value=int(port)
        if 1<=value<=65535 and value not in clean:clean.append(value)
    if not clean:return {}
    deadline=time.monotonic()+max(.05,float(timeout));results={}
    def check():
        if cancel_check and cancel_check():raise ToolCancelled('Native service identification cancelled')
        if time.monotonic()>=deadline:raise TimeoutError('Native service identification timed out')
    def connection(port):
        check();return socket.create_connection((host,port),timeout=min(2,max(.05,deadline-time.monotonic())))
    def identify(port):
        try:
            with connection(port) as peer:
                peer.settimeout(min(.35,max(.05,deadline-time.monotonic())))
                try:banner=peer.recv(1024)
                except socket.timeout:banner=b''
                if banner.startswith(b'SSH-'):
                    label=banner.splitlines()[0].decode('utf-8','replace');return PortInfo(port_id=port,service_name='ssh',version=label,product='SSH')
                if banner.startswith(b'220'):
                    label=banner.decode('utf-8','replace').strip();service='ftp' if 'ftp' in label.lower() else 'smtp';return PortInfo(port_id=port,service_name=service,version=label)
                if len(banner)>5 and banner[4]==10:
                    version=banner[5:].split(b'\0',1)[0].decode('utf-8','replace');return PortInfo(port_id=port,service_name='mysql',product='MySQL',version=version)
                check();peer.settimeout(min(1.5,max(.05,deadline-time.monotonic())))
                authority=('['+host+']') if ':' in host else host
                peer.sendall(('GET / HTTP/1.0\r\nHost: '+authority+'\r\nConnection: close\r\n\r\n').encode('ascii','strict'))
                try:response=peer.recv(8192)
                except (socket.timeout,ConnectionResetError):response=b''
            service='http'
            if port in (443,8443,9443) or not response.startswith(b'HTTP/') or b'plain http request' in response.lower() and b'https' in response.lower():
                check()
                plain_response=response
                try:
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
                    with connection(port) as raw,context.wrap_socket(raw,server_hostname=host) as peer:
                        peer.settimeout(min(1.5,max(.05,deadline-time.monotonic())))
                        peer.sendall(('GET / HTTP/1.0\r\nHost: '+authority+'\r\nConnection: close\r\n\r\n').encode('ascii','strict'));response=peer.recv(8192);service='https'
                except (OSError,ssl.SSLError):
                    if not plain_response.startswith(b'HTTP/'):return PortInfo(port_id=port,service_name='unknown')
                    response=plain_response;service='http'
            if not response.startswith(b'HTTP/'):return PortInfo(port_id=port,service_name='unknown')
            header=response.split(b'\r\n\r\n',1)[0].decode('iso-8859-1');match=re.search(r'^Server:\s*([^\r\n]+)',header,re.M|re.I)
            label=match[1].strip() if match else '';product,separator,version=label.partition('/')
            return PortInfo(port_id=port,service_name=service,product=product,version=version if separator else label)
        except ToolCancelled:raise
        except (OSError,ValueError,TimeoutError):return None
    check();pool=ThreadPoolExecutor(max_workers=min(8,len(clean)))
    try:
        futures={pool.submit(identify,port):port for port in clean}
        for future in as_completed(futures,timeout=max(.05,deadline-time.monotonic())):
            check();value=future.result()
            if value:results[value.port_id]=value
    except TimeoutError:pass
    finally:pool.shutdown(wait=True,cancel_futures=True)
    return results

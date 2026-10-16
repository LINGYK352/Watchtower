"""An isolated Linux guest using QEMU TCG; no Windows features or drivers changed."""
from pathlib import Path
import ctypes
import io
import json
import logging
import os
import socket
import subprocess
import time
import uuid

import paramiko
import pycdlib
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

APP_VERSION = 'v1.21.167-11'
HOST = '127.0.0.1'
SSH_PORT, WEB_PORT, QMP_PORT = 22276, 55576, 45476
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())
logging.getLogger('paramiko.transport').propagate = False


def hidden_flags():
    return subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0


def _available_port(port):
    with socket.socket() as probe:
        probe.bind((HOST, port))


def protect_state(path):
    """Private SSH keys stay in a directory accessible only to this Windows user."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        import csv
        result = subprocess.run(['whoami.exe', '/user', '/fo', 'csv', '/nh'],
                                capture_output=True, check=True, creationflags=hidden_flags())
        sid = next(csv.reader(io.StringIO(result.stdout.decode('utf-8', 'replace'))))[1]
        subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r', '*'+sid+':(OI)(CI)F'],
                       capture_output=True, check=True, creationflags=hidden_flags())


def make_iso(path, files, volume):
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge='1.09', vol_ident=volume)
    streams = []
    try:
        for index, (name, data) in enumerate(files.items()):
            stream = io.BytesIO(data); streams.append(stream)
            iso.add_fp(stream, len(data), iso_path='/FILE%04d.;1' % index,
                       joliet_path='/'+name, rr_name=name)
        iso.write(str(path))
    finally:
        iso.close()


class PortableRuntime:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.state = self.root/'state'
        self.engine = self.root/'engine'
        self.process = None
        settings=self.state/'runtime-settings.json'
        if settings.is_file():
            data=json.loads(settings.read_text())
        elif (self.state/'runtime.json').exists():
            data={'ssh_port':SSH_PORT,'web_port':WEB_PORT,'qmp_port':QMP_PORT,'memory_mib':8192,'cpus':4}
        else:
            held=[]
            try:
                for _ in range(3):
                    sock=socket.socket();sock.bind((HOST,0));held.append(sock)
                ports=[sock.getsockname()[1] for sock in held]
            finally:
                for sock in held:sock.close()
            data={'ssh_port':ports[0],'web_port':ports[1],'qmp_port':ports[2],'memory_mib':8192,'cpus':4,'mac_address':'52:54:00:'+':'.join(uuid.uuid4().hex[i:i+2] for i in [0,2,4])}
        self.ssh_port,self.web_port,self.qmp_port=[int(data[name]) for name in ['ssh_port','web_port','qmp_port']]
        if len({self.ssh_port,self.web_port,self.qmp_port})!=3 or any(not 1024<=v<=65535 for v in [self.ssh_port,self.web_port,self.qmp_port]):raise ValueError('本机端口配置无效')
        self.mac_address=data.get('mac_address','52:54:00:12:34:56')
        if not __import__('re').fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',self.mac_address):raise ValueError('本机网络身份无效')
        self.memory_mib=int(data.get('memory_mib',8192));self.cpus=int(data.get('cpus',4))
        if not 2048<=self.memory_mib<=32768 or not 1<=self.cpus<=16:raise ValueError('运行资源配置无效')
        protect_state(self.state)
        if not settings.exists():settings.write_text(json.dumps(data))
        base_path=self.root/'runtime/base.json'
        self.base=json.loads(base_path.read_text()) if base_path.is_file() else {'file':'debian.qcow2','payload_version':APP_VERSION,'preinstalled':False}
        if not __import__('re').fullmatch(r'[A-Za-z0-9_.-]+\.qcow2',self.base['file']):raise ValueError('基础镜像名称无效')
        self.payload_version=self.base.get('payload_version',APP_VERSION)
        if not __import__('re').fullmatch(r'v\d+\.\d+\.\d+(?:-\d+)?',self.payload_version):raise ValueError('初始化介质版本无效')

    def is_running(self):
        if os.name != 'nt':return bool(self.process and self.process.poll() is None)
        try:
            data=json.loads((self.state/'runtime.json').read_text())
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.OpenProcess.restype=ctypes.c_void_p
            handle=kernel.OpenProcess(0x1000,False,int(data['pid']))
            if not handle:return False
            try:
                buffer=ctypes.create_unicode_buffer(32768);length=ctypes.c_ulong(len(buffer))
                kernel.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_ulong)]
                if not kernel.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(length)):return False
                return Path(buffer.value).resolve()==(self.engine/'qemu-system-x86_64.exe').resolve()
            finally:
                kernel.CloseHandle.argtypes=[ctypes.c_void_p];kernel.CloseHandle(handle)
        except (OSError,ValueError,KeyError):return False

    def prepare(self):
        protect_state(self.state)
        key = self.state/'guest.key'
        if not key.exists():
            private = Ed25519PrivateKey.generate()
            key.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
            public = private.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                       serialization.PublicFormat.OpenSSH).decode()
            config = {'instance-id': 'watchtower-preview-'+uuid.uuid4().hex,
                      'local-hostname': 'watchtower-preview'}
            userdata = {'users': [{'name': 'watchtower', 'lock_passwd': True,
                         'sudo': ['ALL=(ALL) NOPASSWD:ALL'], 'groups': ['sudo'],
                         'ssh_authorized_keys': [public]}], 'ssh_pwauth': False,
                        'disable_root': True, 'timezone': 'Asia/Shanghai',
                        'package_update': False, 'package_upgrade': False,
                        'runcmd': [['bash', '-lc', 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq docker.io > /var/log/watchtower-docker-install.log 2>&1']]}
            if self.base.get('preinstalled'):
                userdata['runcmd']=[['systemctl','enable','--now','docker'],['systemctl','restart','ssh']]
            userdata['ssh_deletekeys']=True
            admin_path=self.state/'admin-init.json'
            if admin_path.is_file():
                admin=json.loads(admin_path.read_text(encoding='utf-8'))
                userdata['write_files']=[{'path':'/opt/watchtower-preview/admin-init.json','owner':'root:root','permissions':'0600','content':json.dumps(admin,ensure_ascii=False)}]
            network={'version':2,'ethernets':{'eth0':{'match':{'macaddress':self.mac_address},'set-name':'eth0','dhcp4':True,'dhcp6':False,'optional':True}}}
            make_iso(self.state/'seed.iso', {'network-config':yaml.safe_dump(network).encode(),'meta-data': yaml.safe_dump(config).encode(),
                       'user-data': ('#cloud-config\n'+yaml.safe_dump(userdata)).encode()}, 'cidata')
        if not (self.state/'empty.iso').exists():
            make_iso(self.state/'empty.iso', {'readme': b'Watchtower preview payload slot'}, 'EMPTY')
        disk = self.state/'guest.qcow2'
        if not disk.exists():
            subprocess.run([str(self.engine/'qemu-img.exe'), 'create', '-f', 'qcow2', '-F', 'qcow2',
                            '-b', '../runtime/'+self.base['file'], 'guest.qcow2', '24G'], cwd=self.state,
                           check=True, capture_output=True, creationflags=hidden_flags())
        else:
            info=json.loads(subprocess.check_output([str(self.engine/'qemu-img.exe'),'info','--output=json','guest.qcow2'],cwd=self.state,creationflags=hidden_flags()))
            previous=info.get('backing-filename','')
            pinned=Path(previous).name
            if not __import__('re').fullmatch(r'[A-Za-z0-9_.-]+\.qcow2',pinned) or not (self.root/'runtime'/pinned).is_file():raise RuntimeError('用户磁盘的原基础镜像缺失；不会自动替换基础磁盘')
            expected='../runtime/'+pinned
            if previous!=expected:
                subprocess.run([str(self.engine/'qemu-img.exe'),'rebase','-u','-f','qcow2','-F','qcow2','-b',expected,'guest.qcow2'],cwd=self.state,check=True,capture_output=True,creationflags=hidden_flags())

    def start(self):
        if self.is_running():return int(json.loads((self.state/'runtime.json').read_text())['pid'])
        self.prepare()
        for port in [self.ssh_port, self.web_port, self.qmp_port]: _available_port(port)
        args = [str(self.engine/'qemu-system-x86_64.exe'), '-L', '../engine/share',
                '-name', 'WatchtowerPreview1676', '-machine', 'q35', '-accel', 'tcg,thread=multi',
                '-cpu', 'max', '-smp', str(self.cpus), '-m', str(self.memory_mib), '-display', 'none', '-monitor', 'none',
                '-serial', 'file:serial.log',
                '-qmp', 'tcp:'+HOST+':'+str(self.qmp_port)+',server=on,wait=off',
                '-drive', 'file=guest.qcow2,if=virtio,format=qcow2',
                '-device', 'virtio-scsi-pci,id=scsi0',
                '-drive', 'id=seed,file=seed.iso,if=none,media=cdrom,format=raw,readonly=on',
                '-device', 'scsi-cd,drive=seed,bus=scsi0.0',
                '-drive', 'id=payload,file=empty.iso,if=none,media=cdrom,format=raw,readonly=on',
                '-device', 'scsi-cd,drive=payload,bus=scsi0.0',
                '-nic', 'user,model=virtio-net-pci,mac='+self.mac_address+',hostfwd=tcp:'+HOST+':'+str(self.ssh_port)+'-:22,hostfwd=tcp:'+HOST+':'+str(self.web_port)+'-:5555']
        with (self.state/'qemu.log').open('ab') as log:
            self.process = subprocess.Popen(args, cwd=self.state, stdout=log, stderr=log,
                                            creationflags=hidden_flags())
        (self.state/'runtime.json').write_text(json.dumps({'pid':self.process.pid,
                    'started_at':time.time(), 'version':APP_VERSION, 'mode':'tcg'}))
        return self.process.pid

    def connect(self, timeout=8):
        client = paramiko.SSHClient()
        hosts = self.state/'known_hosts'
        if hosts.exists(): client.load_host_keys(str(hosts))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, port=self.ssh_port, username='watchtower',
                       key_filename=str(self.state/'guest.key'), timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False)
        client.save_host_keys(str(hosts))
        return client

    def attach_payload(self):
        """Replace only this guest's empty CD slot through its loopback QMP endpoint."""
        with socket.create_connection((HOST, self.qmp_port), timeout=8) as conn:
            stream = conn.makefile('rwb')
            json.loads(stream.readline())
            stream.write(b'{"execute":"qmp_capabilities"}\n');stream.flush()
            while True:
                message=json.loads(stream.readline())
                if 'return' in message:break
                if 'error' in message:raise RuntimeError(str(message['error']))
            command={'execute':'blockdev-change-medium','arguments':{'device':'payload',
                     'filename':'../runtime/payload-'+self.payload_version+'.iso','format':'raw','read-only-mode':'retain','force':True}}
            stream.write(json.dumps(command).encode()+b'\n');stream.flush()
            while True:
                message=json.loads(stream.readline())
                if 'return' in message:break
                if 'error' in message:raise RuntimeError(str(message['error']))

    def provision(self, client, bootstrap=None):
        self.attach_payload()
        script='/mnt/watchtower-payload/bootstrap.sh'
        if bootstrap is not None:
            # The caller validates this versioned resource before transfer. Keep
            # recovery code independent from the multi-gigabyte read-only media.
            stage='/opt/watchtower-preview/bootstrap-'+uuid.uuid4().hex+'.pending'
            _, out, err=client.exec_command('sudo mkdir -p /opt/watchtower-preview; sudo chown watchtower /opt/watchtower-preview', timeout=10)
            if out.channel.recv_exit_status():raise RuntimeError('Cannot prepare initialization recovery')
            transfer=client.open_sftp()
            try:transfer.put(str(bootstrap),stage)
            finally:transfer.close()
            _, out, err=client.exec_command('sudo chmod 644 '+stage+'; sudo mv '+stage+' /opt/watchtower-preview/bootstrap.sh',timeout=10)
            if out.channel.recv_exit_status():raise RuntimeError('Cannot deliver initialization recovery')
            script='/opt/watchtower-preview/bootstrap.sh' 
        command = "sudo bash -c 'set -e; mkdir -p /mnt/watchtower-payload /opt/watchtower-preview; for n in $(seq 1 100); do [ -e /dev/disk/by-label/WATCHTOWER ] && break; sleep 0.2; done; test -e /dev/disk/by-label/WATCHTOWER; mountpoint -q /mnt/watchtower-payload || mount -o ro /dev/disk/by-label/WATCHTOWER /mnt/watchtower-payload; test -r SCRIPT; rm -f /opt/watchtower-preview/error; nohup flock -n /opt/watchtower-preview/bootstrap.lock bash SCRIPT >/opt/watchtower-preview/start.log 2>&1 </dev/null &'"
        _, stdout, stderr = client.exec_command(command.replace('SCRIPT',script), timeout=40)
        if stdout.channel.recv_exit_status():
            raise RuntimeError('Could not start preview bootstrap: '+stderr.read().decode('utf-8','replace')[-500:])


    def stop(self):
        if not self.is_running():raise RuntimeError('本测试实例后台未运行')
        client = self.connect()
        try:client.exec_command('sudo shutdown -h now', timeout=8)
        finally:client.close()

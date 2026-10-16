"""Build a clean Docker/Compose-ready base; never clone a user instance."""
# Build paths resolve from this source checkout, never from cwd.
from pathlib import Path as _BuildPath
import sys as _BuildSys
_BuildSource = _BuildPath(__file__).resolve().parents[1]
_BuildSys.path.insert(0, str(_BuildSource))
from release_tools.workspace_paths import development_paths
_BuildPaths = development_paths(_BuildSource)
WIN_SOURCE = _BuildPaths['source']
WIN_QA = _BuildPaths['validation']
WIN_NATIVE = _BuildPaths['native']
WIN_LEGACY = _BuildPaths['legacy']
WIN_RELEASES = _BuildPaths['releases']
if not WIN_LEGACY.is_dir():
    raise SystemExit('The obsolete Linux VM packaging flow was removed. Use windows_native/build.py for the current native client.')
from pathlib import Path
import json,os,sys,time,subprocess,hashlib
import paramiko
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from windows_preview.portable_runtime import make_iso,protect_state,hidden_flags
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import yaml
root=WIN_LEGACY
work=root/'runtime/build-state';protect_state(work)
engine=root/'engine';runtime=root/'runtime'
key_path=work/'builder.key'
if not key_path.exists():
 key=Ed25519PrivateKey.generate();key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()))
else:key=serialization.load_ssh_private_key(key_path.read_bytes(),None)
public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
user='watchtower-builder'
seed=work/'seed.iso'
userdata={'users':[{'name':user,'lock_passwd':True,'sudo':['ALL=(ALL) NOPASSWD:ALL'],'ssh_authorized_keys':[public]}],'ssh_pwauth':False,'disable_root':True,'timezone':'Asia/Shanghai','package_update':False,'package_upgrade':False}
make_iso(seed,{'meta-data':yaml.safe_dump({'instance-id':'watchtower-clean-runtime-build','local-hostname':'watchtower-build'}).encode(),'user-data':('#cloud-config\n'+yaml.safe_dump(userdata)).encode()},'cidata')
disk=runtime/'debian-docker-working.qcow2'
if not disk.exists():subprocess.run([str(engine/'qemu-img.exe'),'create','-f','qcow2','-F','qcow2','-b','debian.qcow2',disk.name,'6G'],cwd=runtime,check=True,capture_output=True,creationflags=hidden_flags())
args=[str(engine/'qemu-system-x86_64.exe'),'-L','../engine/share','-name','WatchtowerCleanRuntimeBuilder','-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','2048','-display','none','-monitor','none','-serial','file:build-state/serial.log','-drive','file='+disk.name+',if=virtio,format=qcow2,discard=unmap','-device','virtio-scsi-pci,id=scsi0','-drive','id=seed,file=build-state/seed.iso,if=none,media=cdrom,format=raw,readonly=on','-device','scsi-cd,drive=seed,bus=scsi0.0','-nic','user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:22811-:22']
log=(work/'qemu.log').open('ab');proc=subprocess.Popen(args,cwd=runtime,stdout=log,stderr=log,creationflags=hidden_flags())
(work/'build.json').write_text(json.dumps({'pid':proc.pid,'stage':'boot'}))
try:
 for _ in range(150):
  try:
   c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());c.connect('127.0.0.1',port=22811,username=user,key_filename=str(key_path),timeout=5,banner_timeout=5,auth_timeout=5,look_for_keys=False,allow_agent=False);break
  except Exception:
   if proc.poll() is not None:raise RuntimeError('Clean build guest exited; inspect builder serial log')
   time.sleep(2)
 else:raise RuntimeError('Clean build guest did not boot')
 print('Clean guest connected; preparing Docker and Compose.',flush=True)
 command='sudo env DEBIAN_FRONTEND=noninteractive bash -c "apt-get update -qq && apt-get install -y -qq docker.io > /var/log/watchtower-build-packages.log 2>&1"'
 _,out,err=c.exec_command(command,timeout=600)
 if out.channel.recv_exit_status():raise RuntimeError('Docker installation failed: '+err.read().decode()[-400:])
 s=c.open_sftp();s.put(str(root/'source/validation/components/docker-compose'),'/home/'+user+'/docker-compose')
 _,out,err=c.exec_command('sudo install -D -m 755 /home/'+user+'/docker-compose /usr/libexec/docker/cli-plugins/docker-compose; docker --version; docker compose version',timeout=20)
 result=out.read().decode();status=out.channel.recv_exit_status();assert status==0,err.read().decode();print(result.strip(),flush=True)
 cleanup="""#!/bin/bash
set -e
systemctl stop docker.service docker.socket || true
cloud-init clean --logs --machine-id --seed
install -m 444 /dev/null /etc/machine-id
rm -f /var/lib/dbus/machine-id /var/lib/systemd/random-seed
ln -s /etc/machine-id /var/lib/dbus/machine-id
rm -f /etc/ssh/ssh_host_* /root/.bash_history
userdel -f -r watchtower-builder || true
fstrim -av || true
sync
shutdown -h now
"""
 with s.open('/home/'+user+'/clean-runtime.sh','w') as f:f.write(cleanup)
 c.exec_command('sudo bash -c "cp /home/'+user+'/clean-runtime.sh /tmp/clean-runtime.sh; chmod 700 /tmp/clean-runtime.sh; nohup bash -c \'sleep 3; bash /tmp/clean-runtime.sh; rm -f /tmp/clean-runtime.sh\' >/tmp/clean-runtime.log 2>&1 </dev/null &"',timeout=10)
 s.close();c.close()
 for _ in range(150):
  if proc.poll() is not None:break
  time.sleep(1)
 else:raise RuntimeError('Clean build guest has not shut down; refusing image conversion')
 print('Clean guest stopped; flattening read-only base image.',flush=True)
 target=runtime/'debian-preinstalled.qcow2'
 subprocess.run([str(engine/'qemu-img.exe'),'convert','-f','qcow2','-O','qcow2',disk.name,target.name+'.pending'],cwd=runtime,check=True,capture_output=True,creationflags=hidden_flags())
 os.replace(target.with_name(target.name+'.pending'),target)
 info=json.loads(subprocess.check_output([str(engine/'qemu-img.exe'),'info','--output=json',target.name],cwd=runtime,creationflags=hidden_flags()))
 assert not info.get('backing-filename')
 digest=hashlib.sha256(target.read_bytes()).hexdigest()
 receipt={'schema':1,'file':target.name,'sha256':digest,'bytes':target.stat().st_size,'runtime_abi':'linux-amd64-py311-v1','docker_compose_preinstalled':True}
 (runtime/'preinstalled-base.json').write_text(json.dumps(receipt,indent=2))
 (work/'build.json').write_text(json.dumps({'stage':'done','receipt':receipt}));print(json.dumps(receipt),flush=True)
finally:
 log.close()

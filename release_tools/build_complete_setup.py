"""Build a single signed, complete Windows setup EXE from a reviewed program.

The EXE contains the compressed program, not user state. Its installer streams
the appended ZIP range directly, avoiding a second temporary payload copy.
"""
from pathlib import Path
import argparse,base64,hashlib,json,shutil,sys,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from windows_native.embedded_install import FOOTER,MAGIC,Source
from windows_native.update_channel import name
from windows_preview.signed_download import canonical,sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def build(program,stub,output,key_path,testing=True):
    program=Path(program).resolve();output=Path(output).resolve();assert not output.exists()
    version=(program/'app/version.txt').read_text().strip()
    if not testing and '-' in version:raise ValueError('Test version in a stable installer')
    output.parent.mkdir(parents=True,exist_ok=True);payload=output.with_suffix('.payload-building.zip');files={}
    try:
        with zipfile.ZipFile(payload,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for file in sorted(program.rglob('*')):
                if not file.is_file():continue
                relative=file.relative_to(program).as_posix();name(relative)
                if file.is_symlink():raise ValueError('Link in install program')
                files[relative]=sha256(file);archive.write(file,relative)
        manifest={'schema':1,'product':'watchtower-native-install','runtime_abi':'windows-amd64-py311-v1',
            'version':version,'channel':'testing' if testing else 'stable','file':'embedded-payload.zip',
            'bytes':payload.stat().st_size,'sha256':sha256(payload),'files':files}
        raw=Path(key_path).read_bytes();key=Ed25519PrivateKey.from_private_bytes(raw) if len(raw)==32 else load_pem_private_key(raw,None)
        metadata=canonical({'descriptor':manifest,'signature':base64.b64encode(key.sign(canonical(manifest))).decode()})
        shutil.copy2(stub,output);start=output.stat().st_size
        with output.open('ab') as target,payload.open('rb') as source:
            shutil.copyfileobj(source,target,1024*1024);metadata_start=target.tell();target.write(metadata)
            target.write(FOOTER.pack(MAGIC,start,manifest['bytes'],metadata_start,len(metadata)))
        verified=Source(output);verified.verify_payload()
        receipt={'version':version,'file':output.name,'bytes':output.stat().st_size,'sha256':sha256(output),
            'program_bytes':sum((program/n).stat().st_size for n in files),'files':len(files),
            'complete_single_exe':True,'payload_temp_copy_required_at_install':False,'private_state':False,'published':False}
        output.with_suffix('.build.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        return receipt
    finally:
        if payload.exists():payload.resolve().relative_to(output.parent);payload.unlink()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--program',type=Path,required=True);parser.add_argument('--stub',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--sign-key',type=Path,required=True);parser.add_argument('--stable',action='store_true');args=parser.parse_args()
    print(json.dumps(build(args.program,args.stub,args.output,args.sign_key,not args.stable)))

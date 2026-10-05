DLL_HANDLES=[]
from pathlib import Path
import os,sys

def configure(root, core=None, optional=False,runtime=None):
    root=Path(root).resolve();core=Path(core).resolve() if core else root/'app'
    runtime=Path(runtime).resolve() if runtime else root/'runtime'
    sys.path.insert(0,str(core))
    os.environ['PATH']=str(runtime/'tools')+';'+str(runtime/'python')+';'+os.environ.get('PATH','')
    if optional:
        sys.path.insert(1,str(runtime/'browser-python'))
        sys.path.append(str(runtime/'optional/python'))
        for directory in (runtime/'optional/python').glob('*.libs'):
            if hasattr(os,'add_dll_directory'):DLL_HANDLES.append(os.add_dll_directory(str(directory)))
    os.environ['SENTINEL_PLATFORM_CONFIG']=str(root/'state/config.yaml')
    os.environ['SENTINEL_PROXY_RUNTIME_DIR']=str(root/'state/proxy')
    os.environ['SENTINEL_EXTENSION_DIR']=str(root/'state/extensions')
    os.environ['SENTINEL_MIHOMO_BIN']=str(runtime/'tools/mihomo.exe')
    os.environ['PLAYWRIGHT_BROWSERS_PATH']=str(runtime/'browsers')
    manifest=runtime/'browser-component.json'
    if manifest.is_file():
        import json
        data=json.loads(manifest.read_text(encoding='utf-8'))
        binary=runtime/data['chromium_executable'];binary.resolve().relative_to(runtime)
        os.environ['SENTINEL_BROWSER_EXECUTABLE']=str(binary)
    os.environ['SENTINEL_BROWSER_PROFILES']=str(root/'state/browser-profiles')
    os.environ['SENTINEL_NATIVE_ROOT']=str(root)
    os.environ['SENTINEL_NATIVE_SERVICE']=str(runtime/'service/NativeService.exe')
    return root

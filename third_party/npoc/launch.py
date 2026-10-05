from pathlib import Path
import os,sys
root=Path(__file__).resolve().parent.parent
handles=[]
for folder in [root/'optional/python',root/'script-python',root/'npoc-python',root/'npoc']:
 sys.path.insert(0,str(folder))
 for directory in folder.glob('*.libs'):
  if hasattr(os,'add_dll_directory'):handles.append(os.add_dll_directory(str(directory)))
from xing.main import main
main()

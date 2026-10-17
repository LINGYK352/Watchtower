"""Optional, reviewable diagnostics even when the native platform cannot start."""
import queue,threading
from pathlib import Path
from windows_native import diagnostic_report

TEXT={
 'zh-CN':{'title':'Watchtower · 错误诊断','heading':'启动失败','install':'安装失败','note':'下方是即将发送的脱敏日志。仅包含本次失败阶段、错误类型与程序堆栈；不读取配置、密码、授权Key或业务数据。','target':'接收地址：','consent':'我已查看日志，同意上传本次错误诊断','send':'上传错误日志','save':'另存为…','close':'关闭','sending':'正在上传…','sent':'上传成功，报告编号：','saved':'脱敏日志已保存。','failed':'上传失败，本地日志已保留，可稍后重试。','local':'本地日志：'},
 'en-US':{'title':'Watchtower · Error diagnostics','heading':'Startup failed','install':'Installation failed','note':'Review the redacted report below. It contains this failure stage, error types and program frames. Settings, passwords, activation keys and business data are not read.','target':'Destination: ','consent':'I reviewed this report and agree to upload it','send':'Upload error report','save':'Save As…','close':'Close','sending':'Uploading…','sent':'Uploaded. Report ID: ','saved':'Redacted report saved.','failed':'Upload failed. The local report is retained; retry later.','local':'Local log: '}}

def show(diagnostic,phase='startup',parent=None,locale='zh-CN'):
    import tkinter as tk
    from tkinter import ttk,filedialog
    text=TEXT.get(locale,TEXT['zh-CN']);report=diagnostic_report.create(diagnostic,phase);events=queue.Queue();busy=False;closed=False
    window=tk.Toplevel(parent) if parent else tk.Tk();window.title(text['title']);window.geometry('760x610');window.minsize(620,490);window.configure(bg='#101b2c')
    from windows_native.branding import apply
    apply(window)
    if parent:window.transient(parent)
    window.update_idletasks();x=parent.winfo_rootx()+(parent.winfo_width()-760)//2 if parent else (window.winfo_screenwidth()-760)//2;y=parent.winfo_rooty()+(parent.winfo_height()-610)//2 if parent else (window.winfo_screenheight()-610)//2;window.geometry('+%d+%d'%(max(0,x),max(0,y)))
    frame=tk.Frame(window,bg='#101b2c',padx=22,pady=18);frame.pack(fill='both',expand=True)
    tk.Label(frame,text=text['install' if phase=='install' else 'heading'],bg='#101b2c',fg='#f0f5fc',font=('Segoe UI',18,'bold'),anchor='w').pack(fill='x')
    tk.Label(frame,text=report['error_type']+' · '+report['stage'],bg='#101b2c',fg='#8fc9f5',anchor='w').pack(fill='x',pady=(5,9))
    tk.Label(frame,text=text['note'],bg='#101b2c',fg='#afbed2',justify='left',anchor='w',wraplength=700).pack(fill='x')
    tk.Label(frame,text=text['target']+diagnostic_report.DESTINATION,bg='#101b2c',fg='#7cb9ef',anchor='w',wraplength=700,justify='left').pack(fill='x',pady=(9,6))
    area=tk.Frame(frame,bg='#101b2c')
    preview=tk.Text(area,height=6,wrap='word',bg='#17263b',fg='#dae7f5',insertbackground='#dae7f5',relief='flat',font=('Consolas',10),padx=10,pady=10);scroll=ttk.Scrollbar(area,orient='vertical',command=preview.yview);preview.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');preview.pack(side='left',fill='both',expand=True);preview.insert('1.0',diagnostic_report.encode(report).decode('utf-8'));preview.configure(state='disabled')
    local=diagnostic.public().get('log_path','');local_label=tk.Label(frame,text=text['local']+local,bg='#101b2c',fg='#849ab7',anchor='w',wraplength=700,justify='left',font=('Segoe UI',9))
    consent=tk.BooleanVar(value=False)
    def update():send.configure(state='normal' if consent.get() and not busy else 'disabled')
    consent_widget=tk.Checkbutton(frame,text=text['consent'],variable=consent,command=update,bg='#101b2c',fg='#dbe9f7',activebackground='#101b2c',activeforeground='#dbe9f7',selectcolor='#24374f',anchor='w')
    status=tk.Label(frame,text='',bg='#101b2c',fg='#8fc9f5',anchor='w',justify='left',wraplength=700)
    actions=tk.Frame(frame,bg='#101b2c')
    def close():
        nonlocal closed
        closed=True;window.destroy()
    def save():
        chosen=filedialog.asksaveasfilename(parent=window,title=text['save'],defaultextension='.json',initialfile='Watchtower-diagnostic-'+report['report_id'][:8]+'.json',filetypes=[('JSON','*.json')])
        if chosen:
            try:Path(chosen).write_bytes(diagnostic_report.encode(report));status.configure(text=text['saved'])
            except OSError:status.configure(text=text['failed'])
    def upload():
        nonlocal busy
        if busy or not consent.get():return
        busy=True;update();status.configure(text=text['sending'])
        def work():
            try:events.put(('ok',diagnostic_report.send(report,confirmed=True)))
            except Exception as exc:events.put(('error',str(exc)))
        threading.Thread(target=work,daemon=True).start()
    ttk.Button(actions,text=text['close'],command=close).pack(side='right',padx=(8,0));send=ttk.Button(actions,text=text['send'],command=upload,state='disabled');send.pack(side='right',padx=(8,0));ttk.Button(actions,text=text['save'],command=save).pack(side='right')
    actions.pack(side='bottom',fill='x');status.pack(side='bottom',fill='x',pady=(0,5));consent_widget.pack(side='bottom',fill='x',pady=5);local_label.pack(side='bottom',fill='x',pady=(7,3));area.pack(fill='both',expand=True)
    def poll():
        nonlocal busy
        if closed:return
        while not events.empty():
            kind,value=events.get();busy=False
            if kind=='ok':status.configure(text=text['sent']+str(value['id']));consent.set(False)
            else:status.configure(text=text['failed']+' '+str(value)[:180])
            update()
        window.after(100,poll)
    window.protocol('WM_DELETE_WINDOW',close);poll();window.lift();window.attributes('-topmost',True);window.after(600,lambda:window.attributes('-topmost',False))
    if parent:window.grab_set();parent.wait_window(window)
    else:window.mainloop()

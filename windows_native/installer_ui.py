"""Branded native maintenance UI; intentionally works without WebView2."""
from pathlib import Path
import os,json,queue,threading,subprocess
def show(source,diagnostic,root=None,uninstall_only=False):
    import tkinter as tk
    from tkinter import ttk,filedialog,messagebox
    from windows_native import branding,maintenance
    from windows_native.repair_install import recognized
    from windows_native.setup import install
    from windows_native.startup_diagnostics import StartupDiagnostics,redact
    from windows_native.shortcut import create
    window=tk.Tk();branding.apply(window);colors=branding.palette();window.configure(bg=colors['bg']);window.title('瞭望塔 Watchtower · 安装与维护');window.minsize(660,560)
    width=min(780,window.winfo_screenwidth()-48);height=min(650,window.winfo_screenheight()-72);window.geometry(f'{width}x{height}');window.update_idletasks();window.geometry('+%d+%d'%((window.winfo_screenwidth()-width)//2,(window.winfo_screenheight()-height)//2))
    style=ttk.Style(window);style.theme_use('clam');style.configure('TCombobox',fieldbackground=colors['card'],background=colors['card'],foreground=colors['text'],padding=5);style.configure('WT.Horizontal.TProgressbar',troughcolor=colors['border'],background=colors['accent'],borderwidth=0,thickness=5)
    try:
        release=json.loads((branding.assets()/'release.json').read_text());version=release['version']+' · '+release.get('installer_revision','')
    except (OSError,ValueError,KeyError):version='v1.21.178'
    texts={
     'zh-CN':{'title':'安装与维护','sub':'为每一次协作做好准备','install':'全新安装','repair':'修复安装','uninstall':'卸载程序','folder':'安装目录','browse':'浏览…','user':'管理员账号','password':'管理员密码（至少6位）','install_note':'首次安装到空目录。内置必要组件，自动准备WebView2离线运行库。','repair_note':'修复缺失或损坏的程序、卡住的更新。账号、激活、配置和业务资料保持。','uninstall_note':'仅卸载此目录的Watchtower程序，默认保留个人数据；不会卸载共享WebView2运行库。','remove_data':'同时删除此安装的账号、激活、配置、会话和证据（不可恢复）','idle':'请选择操作并确认安装目录','ready':'操作完成','install_action':'开始安装','repair_action':'开始修复','uninstall_action':'卸载此安装','close':'关闭','open':'打开 Watchtower','logs':'查看诊断','busy':'正在处理，请稍候…','error':'操作未完成','check':'请填写空目录、管理员账号及至少6位密码。','existing':'请选择已有的Watchtower安装目录。','confirm_title':'确认卸载','keep_confirm':'即将卸载程序。账号、激活、配置、任务与证据将保留。','purge_confirm':'即将卸载程序并删除此目录全部个人数据，此操作不可恢复。','legal':'包含微软WebView2组件，按微软许可安装；不会上传账号或业务资料。','components':'完整运行组件  ·  离线WebView2  ·  保留资料修复','done_keep':'程序已卸载，个人数据已保留。','done_purge':'程序与此安装的个人数据已删除。','done_repair':'修复完成，原账号与资料已保留。','done_install':'安装完成，可打开Watchtower继续配置。','missing_media':'修复/新装需要官网完整安装器；当前维护工具可用于卸载。'},
     'en-US':{'title':'Install and maintain','sub':'Ready for your next collaboration','install':'New installation','repair':'Repair installation','uninstall':'Uninstall','folder':'Installation folder','browse':'Browse…','user':'Administrator account','password':'Administrator password (6+ characters)','install_note':'Install into an empty folder. Required components and the offline WebView2 runtime are included.','repair_note':'Repair damaged program files and interrupted updates, retaining accounts, activation, settings and business data.','uninstall_note':'Uninstall only this Watchtower installation. Personal data is retained by default; shared WebView2 is kept.','remove_data':'Also delete this installation’s accounts, settings, sessions and evidence (irreversible)','idle':'Choose an action and verify the installation folder','ready':'Completed','install_action':'Install','repair_action':'Repair','uninstall_action':'Uninstall this installation','close':'Close','open':'Open Watchtower','logs':'Review diagnostics','busy':'Working, please wait…','error':'Operation incomplete','check':'Enter an empty folder, administrator name and a password of at least6 characters.','existing':'Choose an existing Watchtower installation.','confirm_title':'Confirm uninstall','keep_confirm':'Uninstall the program while retaining accounts, activation, settings, tasks and evidence?','purge_confirm':'Uninstall and permanently delete all personal data for this installation?','legal':'Includes Microsoft WebView2 under Microsoft’s terms. Accounts and business data are not uploaded.','components':'Complete runtime  ·  Offline WebView2  ·  Preserving repair','done_keep':'Uninstalled. Personal data retained.','done_purge':'Program and this installation’s personal data removed.','done_repair':'Repair complete. Existing accounts and data retained.','done_install':'Installed. Open Watchtower to continue.','missing_media':'Repair/new installation requires the complete website installer. This maintenance tool supports uninstall.'}}
    locale=tk.StringVar(value='zh-CN');destination=tk.StringVar(value=str(root or Path(os.environ['LOCALAPPDATA'])/'Watchtower'));mode=tk.StringVar(value='uninstall' if uninstall_only else 'repair' if recognized(Path(destination.get())) else 'install');username=tk.StringVar();password=tk.StringVar();purge=tk.BooleanVar(value=False);events=queue.Queue();busy=False;finished=False;attempt=None
    def label(parent,text='',size=10,bold=False,color='text',**kw):return tk.Label(parent,text=text,bg=parent.cget('bg'),fg=colors[color],font=('Segoe UI',size,'bold' if bold else 'normal'),**kw)
    shell=tk.Frame(window,bg=colors['bg'],padx=28,pady=22);shell.pack(fill='both',expand=True);header=tk.Frame(shell,bg=colors['bg']);header.pack(fill='x',pady=(0,20))
    try:
        logo=tk.PhotoImage(file=str(branding.assets()/'watchtower.png'));logo=logo.subsample(max(1,logo.width()//52));window._watchtower_logo=logo;tk.Label(header,image=logo,bg=colors['bg']).pack(side='left',padx=(0,13))
    except Exception:pass
    wordmark=tk.Frame(header,bg=colors['bg']);wordmark.pack(side='left');label(wordmark,'瞭望塔 Watchtower',20,True,anchor='w').pack(anchor='w');subtitle=label(wordmark,size=10,color='muted',anchor='w');subtitle.pack(anchor='w',pady=(3,0));picker=ttk.Combobox(header,textvariable=locale,values=list(texts),state='readonly',width=9);picker.pack(side='right',anchor='n')
    viewport=tk.Frame(shell,bg=colors['bg']);viewport.pack(fill='both',expand=True)
    canvas=tk.Canvas(viewport,bg=colors['card'],highlightthickness=1,highlightbackground=colors['border'],borderwidth=0,yscrollincrement=18);scrollbar=ttk.Scrollbar(viewport,orient='vertical',command=canvas.yview);canvas.configure(yscrollcommand=scrollbar.set);canvas.pack(side='left',fill='both',expand=True)
    card=tk.Frame(canvas,bg=colors['card'],padx=22,pady=18);card_item=canvas.create_window((0,0),window=card,anchor='nw')
    def size_card(event=None):
        canvas.itemconfigure(card_item,width=max(1,canvas.winfo_width()-2));canvas.configure(scrollregion=canvas.bbox('all'))
        if card.winfo_reqheight()>canvas.winfo_height()+2:scrollbar.pack(side='right',fill='y')
        else:scrollbar.pack_forget()
    canvas.bind('<Configure>',size_card);card.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
    def wheel(event):
        x,y=window.winfo_pointerxy()
        if canvas.winfo_rootx()<=x<=canvas.winfo_rootx()+canvas.winfo_width() and canvas.winfo_rooty()<=y<=canvas.winfo_rooty()+canvas.winfo_height():canvas.yview_scroll(-1 if event.delta>0 else 1,'units')
    window.bind_all('<MouseWheel>',wheel,add='+');heading=tk.Frame(card,bg=colors['card']);heading.pack(fill='x');title=label(heading,size=15,bold=True);title.pack(side='left');label(heading,version,9,color='muted').pack(side='right')
    choices=tk.Frame(card,bg=colors['card']);choices.pack(fill='x',pady=(17,12));buttons={}
    def select(value):
        if not busy:mode.set(value);purge.set(False)
    for value in ('install','repair','uninstall'):
        button=tk.Button(choices,command=lambda v=value:select(v),relief='flat',borderwidth=0,padx=18,pady=9,cursor='hand2',font=('Segoe UI',10));button.pack(side='left',fill='x',expand=True,padx=(0,5));buttons[value]=button
    note=label(card,color='muted',anchor='w',justify='left',wraplength=640);note.pack(fill='x',pady=(0,17));folder_label=label(card,anchor='w');folder_label.pack(fill='x',pady=(0,6));folder_row=tk.Frame(card,bg=colors['card']);folder_row.pack(fill='x');entry_options={'relief':'flat','borderwidth':0,'highlightthickness':1,'highlightbackground':colors['border'],'highlightcolor':colors['accent'],'bg':colors['bg'],'fg':colors['text'],'insertbackground':colors['text'],'font':('Segoe UI',10)}
    folder=tk.Entry(folder_row,textvariable=destination,**entry_options);folder.pack(side='left',fill='x',expand=True,ipady=8)
    def browse():
        path=Path(destination.get()).expanduser()
        while not path.is_dir() and path!=path.parent:path=path.parent
        chosen=filedialog.askdirectory(parent=window,initialdir=str(path),mustexist=True)
        if chosen:destination.set(chosen)
    browse_button=tk.Button(folder_row,command=browse,relief='flat',bg=colors['soft'],fg=colors['text'],padx=14,pady=8,cursor='hand2');browse_button.pack(side='right',padx=(10,0))
    account_frame=tk.Frame(card,bg=colors['card']);account_frame.pack(fill='x',pady=(15,0));account_frame.columnconfigure(0,weight=1);account_frame.columnconfigure(1,weight=1);user_label=label(account_frame,anchor='w');user_label.grid(row=0,column=0,sticky='w');pass_label=label(account_frame,anchor='w');pass_label.grid(row=0,column=1,sticky='w',padx=(12,0));user_entry=tk.Entry(account_frame,textvariable=username,**entry_options);user_entry.grid(row=1,column=0,sticky='ew',ipady=8,pady=(5,0));pass_entry=tk.Entry(account_frame,textvariable=password,show='●',**entry_options);pass_entry.grid(row=1,column=1,sticky='ew',ipady=8,padx=(12,0),pady=(5,0))
    purge_box=tk.Checkbutton(card,variable=purge,bg=colors['card'],fg=colors['danger'],activebackground=colors['card'],activeforeground=colors['danger'],selectcolor=colors['card'],anchor='w',font=('Segoe UI',9),wraplength=620,justify='left');component_label=label(card,color='muted',anchor='w',wraplength=630);component_label.pack(side='bottom',fill='x',pady=(18,0))
    footer=tk.Frame(shell,bg=colors['bg']);footer.pack(fill='x',pady=(18,0));status=label(footer,color='muted',anchor='w',justify='left',wraplength=660);status.pack(fill='x',pady=(0,8));bar=ttk.Progressbar(footer,style='WT.Horizontal.TProgressbar',mode='indeterminate');bar.pack(fill='x',pady=(0,12));actions=tk.Frame(footer,bg=colors['bg']);actions.pack(fill='x');log_button=tk.Button(actions,relief='flat',bg=colors['bg'],fg=colors['accent'],cursor='hand2');close_button=tk.Button(actions,relief='flat',bg=colors['soft'],fg=colors['text'],padx=18,pady=9);close_button.pack(side='right',padx=(9,0));primary=tk.Button(actions,relief='flat',bg=colors['accent'],fg='white',activeforeground='white',padx=24,pady=9,cursor='hand2',font=('Segoe UI',10,'bold'));primary.pack(side='right');legal=label(shell,color='muted',size=8,anchor='w',wraplength=680);legal.pack(fill='x',pady=(12,0))
    def update(*args):
        text=texts[locale.get()];value=mode.get();title.configure(text=text['title']);subtitle.configure(text=text['sub']);note.configure(text=text[value+'_note']);folder_label.configure(text=text['folder']);browse_button.configure(text=text['browse']);user_label.configure(text=text['user']);pass_label.configure(text=text['password']);purge_box.configure(text=text['remove_data']);component_label.configure(text=text['components']);legal.configure(text=text['legal']);close_button.configure(text=text['close']);log_button.configure(text=text['logs']);primary.configure(text=text['open'] if finished and value!='uninstall' else text[value+'_action'],bg=colors['danger'] if value=='uninstall' else colors['accent'])
        for key,button in buttons.items():button.configure(text=text[key],bg=colors['soft'] if key==value else colors['card'],fg=colors['accent'] if key==value else colors['muted'],state='disabled' if busy or finished or uninstall_only and key!='uninstall' else 'normal')
        account_frame.pack_forget();purge_box.pack_forget()
        if value=='install':account_frame.pack(fill='x',pady=(15,0),before=component_label)
        if value=='uninstall':purge_box.pack(fill='x',pady=(14,0),before=component_label)
        for widget in (folder,browse_button,user_entry,pass_entry):widget.configure(state='disabled' if busy or finished else 'normal')
        picker.configure(state='disabled' if busy else 'readonly');close_button.configure(state='disabled' if busy else 'normal');purge_box.configure(state='disabled' if busy or finished else 'normal')
    def logs():
        if attempt:
            from windows_native.diagnostic_dialog import show as show_diagnostic
            show_diagnostic(attempt,phase='install',parent=window,locale=locale.get())
    def start():
        nonlocal busy,attempt
        text=texts[locale.get()];action=mode.get();target=Path(destination.get()).resolve()
        if finished:
            if action!='uninstall':subprocess.Popen([str(target/'WatchtowerNative.exe')],cwd=target,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            window.destroy();return
        if busy:return
        if action in ('repair','uninstall') and not recognized(target):messagebox.showerror(text['error'],text['existing'],parent=window);return
        if action=='install' and (not destination.get().strip() or not username.get().strip() or len(password.get())<6):messagebox.showerror(text['error'],text['check'],parent=window);return
        from windows_native.embedded_install import Source
        if action!='uninstall' and not isinstance(source,Source) and not Path(source).is_dir():messagebox.showerror(text['error'],text['missing_media'],parent=window);return
        remove=bool(purge.get())
        if action=='uninstall' and not messagebox.askyesno(text['confirm_title'],text['purge_confirm' if remove else 'keep_confirm'],parent=window,icon='warning'):return
        account={'username':username.get().strip(),'password':password.get()};busy=True;primary.configure(state='disabled');bar.start(12);status.configure(text=text['busy'],fg=colors['muted']);attempt=StartupDiagnostics(diagnostic.root);attempt.stage('uninstalling' if action=='uninstall' else 'installing');update()
        def work():
            try:
                result=maintenance.uninstall(target,remove_data=remove,progress=lambda s:events.put(('progress',s))) if action=='uninstall' else install(source,target,account,mode=action,progress=lambda s:events.put(('progress',s)))
                warnings=[]
                if action!='uninstall':
                    for label,operation in [('桌面入口 / Desktop shortcut',create),('系统卸载入口 / Windows uninstall entry',maintenance.register)]:
                        try:operation(target)
                        except Exception:warnings.append(label+'未能创建，可用完整安装器维护 / could not be created; use the complete installer')
                result['warnings']=warnings;events.put(('done',(action,result)))
            except Exception as exc:attempt.failed(exc);events.put(('error',redact(exc)))
        threading.Thread(target=work,daemon=True).start()
    def close():
        if not busy:window.destroy()
    def poll():
        nonlocal busy,finished
        while not events.empty():
            kind,value=events.get()
            if kind=='progress':status.configure(text=value)
            else:
                busy=False;bar.stop();primary.configure(state='normal');password.set('')
                if kind=='done':
                    finished=True;action,result=value;status.configure(text=texts[locale.get()]['done_keep' if action=='uninstall' and result['user_data_retained'] else 'done_purge' if action=='uninstall' else 'done_repair' if action=='repair' else 'done_install']+(' '+ '; '.join(result.get('warnings',[])) if result.get('warnings') else ''));bar.configure(mode='determinate',value=100);primary.configure(state='disabled' if action=='uninstall' else 'normal')
                else:status.configure(text=value,fg=colors['danger']);log_button.pack(side='left');window.bell()
                update()
        window.after(100,poll)
    def changed(*args):
        if not busy and not finished and mode.get()!='uninstall':mode.set('repair' if recognized(Path(destination.get())) else 'install')
    viewport.pack_forget();legal.pack_forget();footer.pack_forget();legal.pack(side='bottom',fill='x',pady=(10,0));footer.pack(side='bottom',fill='x',pady=(14,0));viewport.pack(side='top',fill='both',expand=True)
    destination.trace_add('write',changed);mode.trace_add('write',update);locale.trace_add('write',update);primary.configure(command=start);close_button.configure(command=close);log_button.configure(command=logs);status.configure(text=texts[locale.get()]['idle']);window.protocol('WM_DELETE_WINDOW',close);update();poll();window.mainloop();return 0

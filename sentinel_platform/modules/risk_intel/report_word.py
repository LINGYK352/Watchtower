"""Annotate the original Word package; compile only public, whitelisted tags."""
from __future__ import annotations
from pathlib import Path,PurePosixPath
from datetime import datetime,timezone,timedelta
import base64,copy,difflib,hashlib,html,io,json,os,re,secrets,shutil,stat,zipfile
from . import report_template as rt
from .report_manual import TOKENS,START,END

LIMIT=20*1024*1024-65536
W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
R='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
NS={'w':W,'r':R,'a':'http://schemas.openxmlformats.org/drawingml/2006/main'}
Q=lambda name:'{'+W+'}'+name

def _xml(raw):
    from lxml import etree
    if len(raw)>8*1024*1024 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():raise ValueError('Word XML过大或包含不支持的实体')
    try:
        root=etree.fromstring(raw,etree.XMLParser(resolve_entities=False,no_network=True,load_dtd=False))
        if root.getroottree().docinfo.doctype:raise ValueError('Word XML不支持DTD')
        return root
    except etree.XMLSyntaxError as exc:raise ValueError('Word XML损坏') from exc

def load(raw):
    if not isinstance(raw,bytes) or len(raw)>LIMIT:raise ValueError('Word文件不得超过20MiB')
    try:
        archive=zipfile.ZipFile(io.BytesIO(raw));items=archive.infolist()
        if len(items)>2048 or sum(item.file_size for item in items)>40*1024*1024:raise ValueError('Word展开体积或文件数量过大')
        parts={};names=set()
        for item in items:
            name=item.filename;path=PurePosixPath(name)
            if item.orig_filename!=name:raise ValueError('Word成员路径被隐式改写')
            if path.is_absolute() or '..' in path.parts or chr(92) in name or ':' in name or any(ord(ch)<32 for ch in name) or name.casefold() in names or stat.S_ISLNK(item.external_attr>>16) or item.flag_bits&1:raise ValueError('Word包包含不安全的成员路径')
            names.add(name.casefold())
            if item.is_dir():continue
            if any(token in name.lower() for token in ('vbaproject','/embeddings/','activex/')):raise ValueError('仅支持不含宏、OLE或ActiveX的docx')
            value=archive.read(item)
            if name.endswith(('.xml','.rels')):
                root=_xml(value)
                for element in root.iter():
                    for attr in element.attrib.values():
                        if re.search(r'\{[\{%#]',attr):raise ValueError('Word属性不支持模板表达式')
                    if element.tag!=Q('t') and re.search(r'\{[\{%#]',element.text or ''):raise ValueError('仅可在正文文字中使用预设标签')
            parts[name]=(item,value)
        if not {'[Content_Types].xml','word/document.xml'}<=parts.keys():raise ValueError('不是有效的docx文档')
        archive.close();return parts
    except (zipfile.BadZipFile,RuntimeError,KeyError,NotImplementedError) as exc:raise ValueError('Word包损坏或不是docx') from exc

def documents(parts):
    from lxml import etree
    result={}
    for name,(_,value) in parts.items():
        if name=='word/document.xml' or re.fullmatch(r'word/(?:header|footer)\d+\.xml',name):
            result[name]=_xml(value)
        elif name.endswith(('.xml','.rels')) and re.search(rb'\{[\{%#]',value):raise ValueError('文档非正文部件含不支持的模板标签')
    if sum(len(tree.findall('.//'+Q('p'))) for tree in result.values())>4000:raise ValueError('Word段落过多')
    if not list(result['word/document.xml'].iter(Q('p'))):
        from lxml import etree
        result['word/document.xml'].find(Q('body')).insert(0,etree.Element(Q('p')))
    return result

def nodes(paragraph):
    return [node for node in paragraph.iter(Q('t')) if next((parent for parent in node.iterancestors() if parent.tag==Q('p')),None) is paragraph]

def text(paragraph):return ''.join(node.text or '' for node in nodes(paragraph))

def replace(paragraph,start,end,value):
    from lxml import etree
    values=nodes(paragraph)
    if not values:
        run=etree.SubElement(paragraph,Q('r'));values=[etree.SubElement(run,Q('t'))]
    positions=[];offset=0
    for node in values:
        content=node.text or '';positions.append((node,offset,offset+len(content)));offset+=len(content)
    left=next((i for i,(_,_,stop) in enumerate(positions) if stop>=start),len(values)-1)
    right=next((i for i,(_,_,stop) in enumerate(positions) if stop>=end),len(values)-1)
    first,a,_=positions[left];last,b,_=positions[right];prefix=(first.text or '')[:start-a];suffix=(last.text or '')[end-b:]
    first.text=prefix+value+(suffix if left==right else '');first.set('{http://www.w3.org/XML/1998/namespace}space','preserve')
    for node,_,_ in positions[left+1:right]:node.text=''
    if left!=right:last.text=suffix

def _apply_text(paragraph,new):
    original=text(paragraph)
    for operation,a,b,c,d in reversed(difflib.SequenceMatcher(a=original,b=new,autojunk=False).get_opcodes()):
        if operation!='equal':replace(paragraph,a,b,new[c:d])

def _paragraphs(trees):
    return {name+'#'+str(index):p for name,tree in trees.items() for index,p in enumerate(tree.iter(Q('p')))}

def preview(raw,edits=None):
    parts=load(raw);trees=documents(parts);paragraphs=_paragraphs(trees);edits=edits or {}
    for key,value in edits.items():
        if key in paragraphs:_apply_text(paragraphs[key],value)
    ids={id(p):key for key,p in paragraphs.items()};sections=[];image_budget=[0];relationships={}
    import posixpath
    for name in trees:
        member=posixpath.join(posixpath.dirname(name),'_rels',posixpath.basename(name)+'.rels')
        relationships[name]={}
        if member in parts:
            for rel in _xml(parts[member][1]):
                target=posixpath.normpath(posixpath.join(posixpath.dirname(name),rel.get('Target','')))
                if rel.get('TargetMode')!='External' and rel.get('Type','').endswith('/image') and target in parts:relationships[name][rel.get('Id')]=target
    def picture(node,part):
        member=relationships[part].get(node.get('{'+R+'}embed'));raw=parts[member][1] if member else b''
        mime='image/png' if raw.startswith(b'\x89PNG\r\n\x1a\n') else 'image/jpeg' if raw.startswith(b'\xff\xd8\xff') else 'image/gif' if raw.startswith((b'GIF89a',b'GIF87a')) else ''
        if not mime or len(raw)>2*1024*1024 or image_budget[0]+len(raw)>6*1024*1024:return '<span contenteditable="false">[Word image]</span>'
        try:
            from PIL import Image
            with Image.open(io.BytesIO(raw)) as image:
                if image.width*image.height>20000000:return '<span contenteditable="false">[Word image]</span>'
        except Exception:return '<span contenteditable="false">[Word image]</span>'
        image_budget[0]+=len(raw)
        return '<img contenteditable="false" alt="Word image" src="data:'+mime+';base64,'+base64.b64encode(raw).decode()+'">'
    def render(element,part):
        if element.tag==Q('p'):
            key=ids[id(element)];content=''
            for node in element.iter():
                if node.tag==Q('t') and node in nodes(element):
                    parent=node.getparent();props=parent.find(Q('rPr')) if parent is not None else None;style=[]
                    if props is not None:
                        if props.find(Q('b')) is not None:style.append('font-weight:700')
                        if props.find(Q('i')) is not None:style.append('font-style:italic')
                        color=props.find(Q('color'))
                        if color is not None and re.fullmatch('[0-9a-fA-F]{6}',color.get(Q('val'),'')):style.append('color:#'+color.get(Q('val')))
                        size=props.find(Q('sz'))
                        if size is not None and (size.get(Q('val')) or '').isdigit():style.append('font-size:'+str(max(8,min(40,int(size.get(Q('val')))/2)))+'pt')
                    content+='<span style="'+';'.join(style)+'">'+html.escape(node.text or '')+'</span>'
                elif node.tag==Q('br'):content+='<br>'
                elif node.tag=='{'+NS['a']+'}blip':content+=picture(node,part)
            return '<p data-word-paragraph="'+html.escape(key,quote=True)+'" contenteditable="true" spellcheck="false">'+(content or '<br>')+'</p>'
        if element.tag==Q('tbl'):return '<table>'+''.join(render(child,part) for child in element if child.tag==Q('tr'))+'</table>'
        if element.tag==Q('tr'):return '<tr>'+''.join(render(child,part) for child in element if child.tag==Q('tc'))+'</tr>'
        if element.tag==Q('tc'):return '<td>'+''.join(render(child,part) for child in element if child.tag in (Q('p'),Q('tbl')))+'</td>'
        if element.tag==Q('document'):return render(element.find(Q('body')),part)
        return ''.join(render(child,part) for child in element if child.tag in (Q('p'),Q('tbl')))
    for name,tree in trees.items():sections.append({'part':name,'html':render(tree,name),'paragraphs':{key:text(p) for key,p in paragraphs.items() if key.startswith(name+'#')}})
    return {'sections':sections,'tags':list(TOKENS),'loop_start':START,'loop_end':END}

def compile_document(raw,edits):
    from lxml import etree
    if not isinstance(edits,dict) or len(edits)>1000 or any(not isinstance(v,str) or len(v)>100000 for v in edits.values()) or sum(map(len,edits.values()))>1000000:raise ValueError('文档编辑内容过大或格式无效')
    parts=load(raw);trees=documents(parts);paragraphs=_paragraphs(trees)
    if any(key not in paragraphs for key in edits):raise ValueError('段落已变化，请重新打开原文档')
    for key,value in edits.items():_apply_text(paragraphs[key],value)
    schema={'version':1,'scalars':[],'loops':[],'images':[],'fixed_kept':[]};tags=0
    changed={key.split('#')[0] for key in edits}
    for name,tree in trees.items():
        inside=False
        for p in list(tree.iter(Q('p'))):
            value=text(p)
            if value.strip() in (START,END):
                changed.add(name)
                opening=value.strip()==START
                if p.getparent().tag!=Q('body') or opening==inside:raise ValueError('漏洞循环须用独占正文段落成对标注，不能嵌套')
                inside=opening;replace(p,0,len(value),'{%p for item in findings %}' if opening else '{%p endfor %}');continue
            if any(token in value for token in ('{%','{#','%}','#}')):raise ValueError('不支持自定义模板表达式，请使用预设标签')
            remaining=re.sub(r'\{\{([^{}]+)\}\}','',value)
            if '{{' in remaining or '}}' in remaining:raise ValueError('标签括号不完整')
            for match in reversed(list(re.finditer(r'\{\{([^{}]+)\}\}',value))):
                token=match.group(1).strip();tags+=1
                changed.add(name)
                if tags>1000 or token not in TOKENS:raise ValueError('仅支持预设字段标签')
                if token=='finding.screenshots':
                    if value.strip()!=match.group(0) or p.getparent().tag!=Q('body'):raise ValueError('图片标签须独占正文段落')
                    begin=copy.deepcopy(p);finish=copy.deepcopy(p)
                    for element,statement in ((begin,'{%p for shot in '+('item.shots' if inside else 'findings[0].shots')+' %}'),(p,'{{ shot }}'),(finish,'{%p endfor %}')):replace(element,0,len(text(element)),statement)
                    p.addprevious(begin);p.addnext(finish);break
                if token.startswith('finding.'):
                    replacement='{{ '+('item.' if inside else 'findings[0].')+token.split('.',1)[1]+' }}'
                else:
                    placeholder='word_'+token.replace('.','_');replacement='{{ '+placeholder+' }}'
                    if not any(item['placeholder']==placeholder for item in schema['scalars']):schema['scalars'].append({'placeholder':placeholder,'semantic':token})
                replace(p,match.start(),match.end(),replacement)
        if inside:raise ValueError('缺少漏洞循环结束标签')
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as archive:
        for name,(info,value) in parts.items():archive.writestr(info,etree.tostring(trees[name],encoding='UTF-8',xml_declaration=True,standalone=True) if name in changed else value)
    return output.getvalue(),schema

def _drafts():return rt.get_repo().collection('report_word_drafts')
def _draft_root():return Path(rt.template_dir()).parent/'word-template-drafts'
def _draft_home(token):
    if not isinstance(token,str) or not re.fullmatch('[0-9a-f]{32}',token):raise ValueError('无效的文档草稿')
    root=_draft_root();path=root/token;path.resolve().relative_to(root.resolve());return path
def discard(token,actor):
    row=_drafts().find_one_and_delete({'_id':token,'owner':actor,'state':{'$in':['open','saved','failed']}})
    if row:
        path=_draft_home(token)
        if path.is_dir() and not path.is_symlink():shutil.rmtree(path)
    return {'ok':True}
def upload(raw,filename,actor):
    if not actor:raise ValueError('需要登录后上传')
    if not str(filename).lower().endswith('.docx'):raise ValueError('请先上传Word .docx基础模板')
    view=preview(raw);now=datetime.now(timezone.utc)
    for old in _drafts().find({'owner':actor,'expires':{'$lt':now},'state':{'$in':['open','saved','failed']}}).limit(20):discard(old['_id'],actor)
    if _drafts().count_documents({'owner':actor,'state':{'$in':['open','claimed']}})>=5:raise ValueError('待编辑文档过多，请先关闭或保存已有草稿')
    token=secrets.token_hex(16);home=_draft_home(token);home.mkdir(parents=True,mode=0o700);path=home/'origin.docx';path.write_bytes(raw)
    from bson import ObjectId
    row={'_id':token,'owner':actor,'state':'open','template_oid':ObjectId(),'filename':Path(str(filename).replace(chr(92),'/')).name[:180],'sha256':hashlib.sha256(raw).hexdigest(),'expires':now+timedelta(hours=2)}
    try:_drafts().insert_one(row)
    except Exception:
        home.resolve().relative_to(_draft_root().resolve());shutil.rmtree(home);raise
    return {'ok':True,'draft_id':token,'source_filename':row['filename'],**view}
def view(template_id):
    if not isinstance(template_id,str) or not re.fullmatch('[0-9a-fA-F]{24}',template_id):raise ValueError('无效的Word模板标识')
    row=rt.repo_coll().find_one({'_id':rt._oid(template_id),'editor_mode':'manual_word'})
    if not row:raise ValueError('Word标注模板不存在')
    raw=Path(rt._abs_template_path(row['origin_path'])).read_bytes()
    return {'ok':True,'template_id':str(row['_id']),'name':row['name'],'revision':row['revision'],'source_filename':row.get('source_filename',''),'edits':row.get('word_edits') or {},**preview(raw,row.get('word_edits') or {})}
def save(payload,actor):
    from bson import ObjectId
    if not isinstance(payload,dict) or not actor:raise ValueError('文档保存请求无效')
    name=payload.get('name');edits=payload.get('edits',{});token=payload.get('draft_id');tid=payload.get('template_id');revision=payload.get('revision')
    if tid is not None and (not isinstance(tid,str) or not re.fullmatch('[0-9a-fA-F]{24}',tid)):raise ValueError('无效的Word模板标识')
    if token is not None and (not isinstance(token,str) or not re.fullmatch('[0-9a-f]{32}',token)):raise ValueError('无效的文档草稿')
    if not isinstance(name,str) or not 1<=len(name.strip())<=120:raise ValueError('模板名称须为1至120字符')
    current=rt.repo_coll().find_one({'_id':rt._oid(tid)}) if tid else None
    if tid and (not current or current.get('editor_mode')!='manual_word' or current.get('builtin')):raise ValueError('仅可编辑Word标注模板')
    if current and (isinstance(revision,bool) or not isinstance(revision,int) or revision!=current.get('revision')):raise ValueError('文档已被其它操作更新，请重新打开')
    draft=_drafts().find_one({'_id':token,'owner':actor}) if token else None
    if token:
        _draft_home(token)
        if not draft:raise ValueError('草稿不存在或不属于当前用户')
        raw=(_draft_home(token)/'origin.docx').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=draft['sha256']:raise ValueError('草稿文件校验失败')
    elif current:raw=Path(rt._abs_template_path(current['origin_path'])).read_bytes()
    else:raise ValueError('请先上传基础Word文档')
    compiled,schema=compile_document(raw,edits);digest=hashlib.sha256(json.dumps({'name':name,'edits':edits},sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    oid=current['_id'] if current else draft['template_oid'];existing=rt.repo_coll().find_one({'_id':oid})
    if token and existing and existing.get('word_submission')==token+':'+digest:return {'ok':True,'template_id':str(oid),'revision':existing['revision'],'status':existing['status']}
    if token and not _drafts().update_one({'_id':token,'owner':actor,'state':'open','expires':{'$gt':datetime.now(timezone.utc)}},{'$set':{'state':'claimed'}}).matched_count:raise ValueError('草稿正在保存或已过期，请刷新后重试')
    home=Path(rt._tpl_root(str(oid)));home.mkdir(parents=True,exist_ok=True);stamp=secrets.token_hex(16);origin=home/('word-origin-'+stamp+'.docx');target=home/('word-template-'+stamp+'.docx')
    fields={'name':name.strip(),'editor_mode':'manual_word','status':'review','need_review':True,'schema':schema,'word_edits':edits,'revision':current['revision']+1 if current else 1,'origin_path':origin.relative_to(Path(rt.template_dir())).as_posix(),'template_path':target.relative_to(Path(rt.template_dir())).as_posix(),'source_filename':draft['filename'] if draft else current.get('source_filename',''),'learn_tokens':0,'update_date':rt._now(),'word_submission':(token or '')+':'+digest}
    try:
        origin.write_bytes(raw);target.write_bytes(compiled)
        if current:
            if not rt.repo_coll().update_one({'_id':oid,'revision':revision,'editor_mode':'manual_word','builtin':{'$ne':True}},{'$set':fields}).matched_count:raise ValueError('文档已更新或删除，请重新打开')
        else:rt.repo_coll().insert_one({**fields,'_id':oid,'created_by':actor,'save_date':rt._now()})
    except Exception:
        if token:_drafts().update_one({'_id':token,'owner':actor,'state':'claimed'},{'$set':{'state':'open'}})
        raise
    if token:_drafts().update_one({'_id':token,'owner':actor},{'$set':{'state':'saved'}})
    return {'ok':True,'template_id':str(oid),'revision':fields['revision'],'status':'review'}

"""Conservative static asset discovery; never execute target JavaScript.

Known literal imports, Vite lists and Webpack filename expressions are supported.
Unknown expressions stay unresolved: a candidate URL is not acquisition evidence.
"""
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_SOURCE = 2 * 1024 * 1024
MAX_TOKENS = 100000
MAX_REFERENCES = 4096
_LEX = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*|\d+')


class Unsupported(ValueError):
    pass


def tokens(text):
    output, index = [], 0
    while index < len(text) and len(output) < MAX_TOKENS:
        char = text[index]
        if char.isspace(): index += 1; continue
        if text.startswith('//', index):
            end = text.find('\n', index+2); index = len(text) if end < 0 else end+1; continue
        if text.startswith('/*', index):
            end = text.find('*/', index+2); index = len(text) if end < 0 else end+2; continue
        start = index
        if char in ('"', "'", '`'):
            quote, value = char, []
            index += 1
            dynamic = False
            while index < len(text) and text[index] != quote:
                char = text[index]
                if quote == '`' and text.startswith('${', index): dynamic = True
                if char == '\\' and index+1 < len(text):
                    index += 1; escape = text[index]
                    width = 2 if escape == 'x' else 4 if escape == 'u' else 0
                    digits = text[index+1:index+1+width]
                    if width and len(digits) == width and re.fullmatch('[0-9a-fA-F]+', digits):
                        value.append(chr(int(digits,16))); index += width
                    else:
                        value.append({'n':'\n','r':'\r','t':'\t'}.get(escape,escape))
                else: value.append(char)
                index += 1
            if index >= len(text): break
            index += 1
            output.append(('dynamic' if dynamic else 'string',''.join(value),start,index)); continue
        match = _LEX.match(text,index)
        if match:
            value = match[0]; index += len(value)
            output.append(('number' if value.isdigit() else 'name',value,start,index)); continue
        operator = next((value for value in ('===','!==','=>','||','&&','==','!=') if text.startswith(value,index)),char)
        index += len(operator); output.append(('symbol',operator,start,index))
    return output, index < len(text)


class Expression:
    def __init__(self, items, index): self.items,self.index,self.depth = items,index,0
    def peek(self): return self.items[self.index][1] if self.index < len(self.items) else ''
    def take(self, expected=None):
        if self.index >= len(self.items): raise Unsupported('incomplete expression')
        token = self.items[self.index]; self.index += 1
        if expected is not None and token[1] != expected: raise Unsupported('unexpected expression')
        return token
    def parse(self):
        self.depth += 1
        if self.depth > 48: raise Unsupported('expression depth')
        try:
            value = self.logical()
            if self.peek() == '?':
                self.take('?'); yes = self.parse(); self.take(':'); no = self.parse()
                value = ('if',value,yes,no)
            return value
        finally: self.depth -= 1
    def logical(self):
        value = self.logical_and()
        while self.peek() == '||':
            op = self.take()[1]; value = (op,value,self.logical_and())
        return value
    def logical_and(self):
        value = self.equality()
        while self.peek() == '&&':
            op = self.take()[1]; value = (op,value,self.equality())
        return value
    def equality(self):
        value = self.addition()
        while self.peek() in ('===','==','!==','!='):
            op=self.take()[1]; value=(op,value,self.addition())
        return value
    def addition(self):
        value=self.primary()
        while self.peek()=='+': self.take('+'); value=('+',value,self.primary())
        return value
    def primary(self):
        token=self.take(); kind,value=token[:2]
        if kind=='string': node=('value',value)
        elif kind=='number': node=('value',int(value))
        elif kind=='name': node=('name',value)
        elif value=='(':
            node=self.parse(); self.take(')')
        elif value=='{':
            pairs={}
            while self.peek()!='}':
                if len(pairs)>=MAX_REFERENCES: raise Unsupported('mapping budget')
                key=self.take()
                if key[0] not in ('number','string','name'): raise Unsupported('computed key')
                self.take(':'); pairs[str(key[1])]=self.parse()
                if self.peek()!=',': break
                self.take(',')
            self.take('}'); node=('object',pairs)
        elif value=='[':
            values=[]
            while self.peek()!=']':
                if len(values)>=MAX_REFERENCES: raise Unsupported('array budget')
                values.append(self.parse())
                if self.peek()!=',': break
                self.take(',')
            self.take(']'); node=('array',values)
        else: raise Unsupported('dynamic expression')
        while self.peek()=='[':
            self.take('['); key=self.parse(); self.take(']'); node=('lookup',node,key)
        return node


def evaluate(node, parameter, identity, bindings, depth=0):
    if depth>64: raise Unsupported('evaluation depth')
    kind=node[0]
    if kind=='value': return node[1]
    if kind=='name':
        if node[1]==parameter: return identity
        if node[1] in bindings: return evaluate(bindings[node[1]],parameter,identity,{},depth+1)
        if node[1] in ('null','undefined'): return None
        raise Unsupported('dynamic identifier')
    if kind=='object': return {key:evaluate(value,parameter,identity,bindings,depth+1) for key,value in node[1].items()}
    if kind=='array': return [evaluate(value,parameter,identity,bindings,depth+1) for value in node[1]]
    if kind=='lookup':
        right=evaluate(node[2],parameter,identity,bindings,depth+1)
        container=node[1]
        if container[0]=='name' and container[1] in bindings: container=bindings[container[1]]
        if container[0]=='object': child=container[1].get(str(right))
        elif container[0]=='array' and isinstance(right,int) and 0<=right<len(container[1]): child=container[1][right]
        else: child=None
        return evaluate(child,parameter,identity,bindings,depth+1) if child is not None else None
    left=evaluate(node[1],parameter,identity,bindings,depth+1)
    if kind=='if': return evaluate(node[2] if left else node[3],parameter,identity,bindings,depth+1)
    if kind=='||' and left: return left
    if kind=='&&' and not left: return left
    right=evaluate(node[2],parameter,identity,bindings,depth+1)
    if kind=='+':
        if isinstance(left,int) and isinstance(right,int): return left+right
        if left is None or right is None: raise Unsupported('unknown filename component')
        return str(left)+str(right)
    if kind in ('||','&&'): return right
    if kind in ('===','=='): return left==right
    if kind in ('!==','!='): return left!=right
    raise Unsupported('unsupported operation')


def identities(node, bindings, parameter, seen=None):
    seen=seen or set(); output=set()
    if node[0]=='object': output.update(node[1])
    elif node[0]=='array': output.update(str(i) for i in range(len(node[1])))
    elif node[0]=='name' and node[1] in bindings and node[1] not in seen:
        output.update(identities(bindings[node[1]],bindings,parameter,seen|{node[1]}))
    elif node[0] in ('==','==='):
        for a,b in ((node[1],node[2]),(node[2],node[1])):
            if a==('name',parameter) and b[0]=='value': output.add(str(b[1]))
    for child in node[1:]:
        if isinstance(child,tuple): output.update(identities(child,bindings,parameter,seen))
    return output


def asset_url(base, value, allow_extensionless=False):
    if not isinstance(value,str) or not value or len(value)>4096 or any(ord(c)<32 for c in value): return ''
    try:
        url=urljoin(base,value); parsed=urlsplit(url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password: return ''
        parsed.port
    except ValueError: return ''
    if not allow_extensionless and not re.search(r'\.(?:m?js|cjs)$',parsed.path,re.I): return ''
    if parsed.path.rsplit('/',1)[-1] in ('.js','.mjs','.cjs'): return ''
    return urlunsplit((parsed.scheme,parsed.netloc,parsed.path,parsed.query,''))


_TAG = re.compile(r'<!--.*?(?:-->|$)|<\s*(script|link|base|style)\b((?:[^>\'\"]|"[^\"]*"|\'[^\']*\')*)>', re.I|re.S)
_ATTR = re.compile(r'([^\s/=<>]+)(?:\s*=\s*(?:"([^\"]*)"|\'([^\']*)\'|([^\s>]+)))?')
_ENTITY = re.compile(r'&(#x[0-9a-f]+|#[0-9]+|amp|quot|apos|lt|gt);',re.I)
_RAW_END = {tag:re.compile(r'</\s*'+tag+r'\s*>',re.I) for tag in ('script','style')}


def attribute_text(value):
    def decode(match):
        token=match[1].lower()
        if token.startswith('#'):
            try:return chr(int(token[2:],16) if token.startswith('#x') else int(token[1:]))
            except (ValueError,OverflowError):return '\ufffd'
        return {'amp':'&','quot':'"','apos':"'",'lt':'<','gt':'>'}[token]
    return _ENTITY.sub(decode,value)


class HTMLAssets:
    """Bounded resource tags, including quoted > and raw script/style bodies.

    Does not depend on optional frozen-interpreter HTML modules. This is static
    discovery, not a DOM implementation or a claim of complete HTML coverage.
    """
    def __init__(self, base): self.base,self.assets,self.first_base=base,[],False
    def feed(self,text):
        cursor=0
        while cursor<len(text):
            match=_TAG.search(text,cursor)
            if not match:break
            cursor=match.end()
            if not match[1]:continue
            tag=match[1].lower();data={}
            for attr in _ATTR.finditer(match[2]):
                data.setdefault(attr[1].lower(),attribute_text(next((v for v in attr.groups()[1:] if v is not None),'')))
            if tag=='base' and data.get('href') and not self.first_base:
                self.base=urljoin(self.base,data['href']);self.first_base=True
            if tag=='script' and data.get('src'):self.assets.append((data['src'],'html_script'))
            relations=data.get('rel','').lower().split()
            if tag=='link' and ('modulepreload' in relations or 'preload' in relations and data.get('as','').lower()=='script') and data.get('href'):
                self.assets.append((data['href'],'html_preload'))
            if tag in ('script','style'):
                end=_RAW_END[tag].search(text,cursor)
                cursor=end.end() if end else len(text)


def discover(text, source_url, document_url=None):
    truncated=len(text)>MAX_SOURCE; text=text[:MAX_SOURCE]
    refs={}; warnings=set(); literals=[]; runtime_ranges=[]; literal_base=source_url
    def add(value,kind,base=source_url,allow_extensionless=False):
        url=asset_url(base,value,allow_extensionless)
        if url and len(refs)<MAX_REFERENCES:
            refs.setdefault(url,{'url':url,'kind':kind,'source_url':source_url,'acquired':False})
    if re.search(r'<(?:!doctype|html|script|link)\b',text[:2048],re.I):
        parser=HTMLAssets(source_url)
        try: parser.feed(text)
        except (ValueError,AssertionError): warnings.add('html_parse_incomplete')
        for ref,kind in parser.assets:add(ref,kind,parser.base,True)
        literal_base=parser.base
    items,token_limit=tokens(text); bindings={}; public_paths={}
    for index,token in enumerate(items):
        if token[0]=='dynamic': warnings.add('dynamic_template')
        if token[1]=='import' and index+2<len(items) and items[index+1][1]=='(' and items[index+2][0] not in ('string',):
            warnings.add('dynamic_import_needs_browser')
        if token[0]=='string': literals.append(token)
        if token[0]=='name' and index+2<len(items) and items[index+1][1]=='=' and items[index+2][1] in ('{','['):
            try: bindings[token[1]]=Expression(items,index+2).parse()
            except Unsupported: pass
        if index+4<len(items) and token[0]=='name' and [x[1] for x in items[index+1:index+4]]==['.','p','=']:
            if items[index+4][0]=='string': public_paths.setdefault(token[1],set()).add(items[index+4][1])
            else: warnings.add('dynamic_public_path')
    for index,token in enumerate(items):
        if index+6>=len(items) or token[0]!='name' or [x[1] for x in items[index+1:index+4]]!=['.','u','=']: continue
        cursor=index+4
        try:
            if items[cursor][1]=='function':
                cursor+=1
                if items[cursor][1]!='(': cursor+=1
                if items[cursor][1]!='(' or items[cursor+2][1]!=')' or items[cursor+3][1]!='{': raise Unsupported('dynamic function parameters')
                parameter=items[cursor+1][1]
                cursor+=4
                if items[cursor][1]!='return': raise Unsupported('dynamic function body')
                cursor+=1
            else:
                parameter=items[cursor+1][1] if items[cursor][1]=='(' else items[cursor][1]
                while cursor<len(items) and items[cursor][1]!='=>': cursor+=1
                cursor+=1
                if cursor<len(items) and items[cursor][1]=='{':
                    cursor+=1
                    if items[cursor][1]!='return': raise Unsupported('dynamic function body')
                    cursor+=1
            expression=Expression(items,cursor); tree=expression.parse()
            if expression.peek() not in (';',',','}','',')'): raise Unsupported('unsupported filename expression')
            runtime_ranges.append((items[cursor][2],items[expression.index-1][3]))
            prefixes=public_paths.get(token[1],set())
            if len(prefixes)>1: raise Unsupported('ambiguous runtime public path')
            prefix=next(iter(prefixes),'')
            base=urljoin(document_url or source_url,prefix) if prefix else source_url
            known=identities(tree,bindings,parameter)
            if not known: warnings.add('runtime_ids_unknown')
            for identity in sorted(known)[:MAX_REFERENCES]:
                argument=int(identity) if identity.isdigit() else identity
                filename=evaluate(tree,parameter,argument,bindings)
                if isinstance(filename,str):add(filename,'webpack_chunk',base)
        except (Unsupported,IndexError,RecursionError): warnings.add('runtime_expression_needs_browser')
    for token in literals:
        if not any(start<=token[2]<end for start,end in runtime_ranges):
            base=literal_base
            if '__vite__mapDeps' in text and token[1].startswith('assets/'):
                if document_url and urlsplit(document_url).netloc==urlsplit(source_url).netloc: base=document_url
                else: base=urljoin(source_url,'../')
            add(token[1],'literal_asset',base)
    if truncated or token_limit or len(refs)>=MAX_REFERENCES: warnings.add('parser_budget_reached')
    return {'source_url':source_url,'references':list(refs.values()),'reference_count':len(refs),
            'incomplete_reasons':sorted(warnings),'truncated':truncated or token_limit,
            'candidate_only':True,'complete_site_coverage':False}

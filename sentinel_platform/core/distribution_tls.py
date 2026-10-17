"""Verified distribution HTTPS shared by activation and native updates.

Windows default trust combines OS server-auth roots and the shipped public CA
bundle. Explicit CA configuration remains authoritative. No unverified context,
HTTP downgrade, credential fallback or process-local authentication state.
This stdlib-first file is also bundled as SDK data for rollback independence.
"""
from __future__ import annotations
import os,ssl
from urllib.request import HTTPSHandler,build_opener,urlopen as _urlopen

def windows():return os.name=='nt'

def verified_context(cafile=None):
    custom=next((os.environ.get(name) for name in ('REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','SSL_CERT_FILE','SSL_CERT_DIR') if os.environ.get(name)),None)
    if custom:
        # Never silently replace an explicitly configured trust/pinning bundle.
        context=ssl.create_default_context(capath=custom) if os.path.isdir(custom) else ssl.create_default_context(cafile=custom)
    else:
        context=ssl.create_default_context()
        if windows():
            if cafile is None:
                import certifi
                cafile=certifi.where()
            context.load_verify_locations(cafile=str(cafile))
    if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:raise RuntimeError('Distribution HTTPS verification is required')
    return context

def verified_opener(*handlers,cafile=None):
    if windows():return build_opener(*handlers,HTTPSHandler(context=verified_context(cafile)))
    return build_opener(*handlers)

class VerifiedOpener:
    def __init__(self,*handlers):self.handlers=handlers
    def open(self,*args,**kwargs):return verified_opener(*self.handlers).open(*args,**kwargs)

def urlopen(request,*args,**kwargs):
    if not windows():return _urlopen(request,*args,**kwargs)
    if kwargs.get('context') is not None:
        context=kwargs['context']
        if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:raise ValueError('Distribution HTTPS verification cannot be disabled')
        return _urlopen(request,*args,**kwargs)
    # Existing stdlib ProxyHandler and caller headers are preserved.
    return verified_opener().open(request,*args,**kwargs)

def post(url,**kwargs):
    import requests
    if not windows():return requests.post(url,**kwargs)
    if 'verify' in kwargs and kwargs['verify'] is not True and not isinstance(kwargs['verify'],(str,bytes)):raise ValueError('Distribution HTTPS verification cannot be disabled')
    # Requests already implements explicit CA file/directory handling. Preserve
    # that contract rather than broadening an administrator-specified CA set.
    if isinstance(kwargs.get('verify'),(str,bytes)) or os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('CURL_CA_BUNDLE'):
        return requests.post(url,**kwargs)
    from requests.adapters import HTTPAdapter
    context=verified_context()
    class VerifiedAdapter(HTTPAdapter):
        def init_poolmanager(self,*args,**options):
            options['ssl_context']=context
            return super().init_poolmanager(*args,**options)
        def proxy_manager_for(self,proxy,**options):
            options['ssl_context']=context
            if str(proxy).lower().startswith('https://'):options['proxy_ssl_context']=context
            return super().proxy_manager_for(proxy,**options)
    with requests.Session() as session:
        session.mount('https://',VerifiedAdapter())
        return session.post(url,**kwargs)

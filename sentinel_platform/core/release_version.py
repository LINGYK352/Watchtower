"""Business version labels/comparison, independent of the pinned update controller.

Generated from the shared wire grammar; parity is checked against control policy.
This module grants no update, rollback, signature or installation authority.
"""
import re
PATCH_OFFSET=1_000_000
PATCH_MAX=999_999

def key(version):
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?', version or '')
    if not match:raise ValueError('Invalid update version')
    main=tuple(map(int,match.groups()[:3]));number=int(match[4]) if match[4] else None
    if number is None:return main+(1,0)
    if number==PATCH_OFFSET or number>PATCH_OFFSET+PATCH_MAX:raise ValueError('Reserved patch marker or patch range exceeded')
    return main+((2,number-PATCH_OFFSET) if number>PATCH_OFFSET else (0,number))

def is_test(version):return key(version)[3]==0

def feature_version(version):
    value=key(version)
    return 'v'+'.'.join(map(str,value[:3]))

def display_version(version):return feature_version(version) if key(version)[3]==2 else version

def patch_version(feature,number):
    value=key(feature)
    if value[3]!=1 or type(number) is not int or not 1<=number<=PATCH_MAX:raise ValueError('Patch requires a formal feature and positive bounded patch number')
    return feature+'-'+str(PATCH_OFFSET+number)

def patch_id(version,system):
    value=key(version)
    if value[3]!=2:return ''
    if system not in ('linux','win'):raise ValueError('Unsupported patch system')
    return 'W-'+system+'-'+str(value[2])+'B-'+str(value[4])

def release_kind(version):return ('test','feature','patch')[key(version)[3]]

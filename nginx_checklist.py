# -*- coding: utf-8 -*-
'''
Nginx Security Benchmark module
'''

import re	
import logging
import pwd
from salt import utils 
#from packaging import version
from distutils.version import LooseVersion, StrictVersion
__virtualname__ = 'nginx_se'
__outputter__ = {'run': 'nested'}


GREP = utils.which('egrep')
CHAGE = utils.which('chage')
RPMQUERY = utils.which('rpm')
STAT = utils.which('stat')
if utils.which('chkconfig'):
    CHKCONFIG = utils.which('chkconfig')
if utils.which('systemctl'):
    CHKCONFIG = utils.which('systemctl')

PASSED = 'Passed'
FAILED = 'Failed'
UNKNOWN = 'Unknown'
KEYS_MAP = {
    'id': 'id',
    'os': 'os',
    'osrelease': 'os_release'
}

nginx_benchmark = {}
log = logging.getLogger(__name__)

def __virtual__():
    '''
    Only load module on Linux
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
	return __virtualname__
    return False

def run():
    '''
    Nginx Security Benchmark
    '''
    nginx_se.update({v: __grain__[k] for k, v in KEYS_MAP.iteritems() if k in __grains__[k] })
    nginx_se['type'] = 'nginx'
    nginx_se['benchmark'] = [
	_audit_1()    
    ]
    return nginx_se

def version():
    '''
    Verify version nginx 
    '''
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    out = __salt__['nginx.version']().splitlines()
    configs.append(out[0])
    version = re.search( r'^(.*)/(\d+.\d+.\d+)$', out[0], re.M | re.I).group(2)
    configs.append(version)
    if LooseVersion(version) > LooseVersion('1.6.3'):
	configs.append('Current nginx version >= 1.6.3 OK')
    else:
	configs.append('Current nginx version <= 1.6.3 FALSE')
	state = FAILED
    return { 'id': _id, 'state': state, 'configs': configs }
def user_nginx():
    '''
    Verify server has user nginx to run nginx 
    '''
    _id = 'nginx_user_verify'
    configs = []
    state = PASSED
    cmd = 'id nginx'
    out = __salt__['cmd.run'](cmd).splitlines()
    not_exist_user = re.search( r'^(.*)(no such user)$', out[0], re.M | re.I)
    if not not_exist_user:
	configs.append("User nginx exists OK")
    else:
	configs.append("User nginx is not exists FAILED")
	state = FAILED
    return { 'id': _id, 'state': state, 'configs': configs }
    







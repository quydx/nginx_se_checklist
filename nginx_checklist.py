# -*- coding: utf-8 -*-
'''
Nginx Security Benchmark module
'''

import stat
import os
import re
import logging
from salt import utils
from distutils.version import LooseVersion

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
NGINX_CONFIG_FILE = '/etc/nginx/nginx.conf'
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


def has_config(config):
    """ Reuse function to check if a line is in the file  """
    config_check = config + '\n'
    with open(NGINX_CONFIG_FILE) as file:
        if any(line == config_check for line in file):
            return True
        else:
            return False


def version():
    '''
    Verify version nginx 
    '''
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    out = __salt__['nginx.version']().splitlines()
    configs.append(out[0])
    nginx_version = re.search(r'^(.*)/(\d+.\d+.\d+)$', out[0], re.M | re.I).group(2)
    configs.append(nginx_version)
    if LooseVersion(version) >= LooseVersion('1.6.3'):
        configs.append('Current nginx version >= 1.6.3 OK')
    else:
        configs.append('Current nginx version < 1.6.3 FALSE')
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def user_nginx():
    '''
    Verify server has user nginx to run nginx 
    '''
    _id = 'nginx_user_verify'
    configs = []
    state = PASSED
    cmd = 'id nginx'
    out = __salt__['cmd.run'](cmd).splitlines()
    not_exist_user = re.search(r'^(.*)(no such user)$', out[0], re.M | re.I)
    if not not_exist_user:
        configs.append("User nginx exists OK")
    else:
        configs.append("User nginx is not exists FAILED")
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def hide_vesion_check():
    """ Function check if nginx is hide version  """
    _id = 'nginx_verison_verify'
    configs = []
    state = PASSED
    config = 'server_tokens off;'
    if has_config(config):
        configs.append('Config hide version nginx is on OK')
    else:
        configs.append('Config hide version nginx is off FALSE')
    return {'id': _id, 'state': state, 'configs': configs}


def unusable_modules():
    """
    Verify unusable module is disable
    """
    _id = 'nginx_verison_verify'
    configs = []
    state = PASSED
    cmd = 'nginx -V'
    out = __salt__['cmd.run'](cmd)
    not_use_modules = ['mail_pop', 'mail_imap', 'http_scgi', 'http_uwsgi']
    for mod in not_use_modules:
        if mod in out:
            configs.append(mod + ' Unusable mail_pop is installed')
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def disable_autoindex():
    """ Verify nginx auto index is disable """
    _id = 'nginx_disable_autoindedx_verify'
    configs = []
    state = PASSED
    config = 'server_tokens off;'
    if has_config(config):
        configs.append('Config hide version nginx is on OK')
    else:
        configs.append('Config hide version nginx is off FALSE')
    return {'id': _id, 'state': state, 'configs': configs}


"""6a"""


def folder_permission():
    """
        Verify unusable module is disable
    """
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    cmd = 'find /etc/nginx -type d -printf "%m:%f\n"'
    out = __salt__['cmd.run'](cmd).splitlines()
    permissions = list(set(out.split(":")[0]))
    if not len(permissions) == 1:
        configs.append("folder permission has value difference to 755")
        configs.append(out)
        state = FAILED
    else:
        if list(set(out.split(":")[0])) == '775':
            configs.append('All folder has permission 755 OK')
    return {'id': _id, 'state': state, 'configs': configs}


def audit6b():
    """
        Verify disable execute permission in nginx upload folder
    """
    nginx_upload_path = '/etc/nginx/upload'
    _id = 'nginx_disable_execute_permission_of_upload_folder'
    configs = []
    state = PASSED
    cmd = 'find ' + nginx_upload_path +' -type d -printf "%m:%f\n"
    out = __salt__['cmd.run'](cmd).splitlines()
    count = 0
    for line in out:
        if line[0] == 'd':
            pass
        else:
            line_separate = line.split()
            if 'x' in line_separate[0]:
                configs.append('Exist executable in nginx upload folder')
                configs.append(line)
                count++
    if count > 0:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


if __name__ == '__main__':
    pass

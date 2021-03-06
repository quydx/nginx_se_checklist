# -*- coding: utf-8 -*-
"""
Nginx Security Benchmark module
"""

import re
import logging
from salt import utils
from distutils.version import LooseVersion
import os.path


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
PHP_CONFIG_FILE = '/etc/php.ini'
KEYS_MAP = {
    'id': 'id',
    'os': 'os',
    'osrelease': 'os_release'
}

nginx_benchmark = {}
log = logging.getLogger(__name__)


def __virtual__():
    """
    Only load module on Linux
    """
    if 'Linux' in __salt__['grains.get']('kernel'):
        return __virtualname__
    return False


def run():
    """
    Operation System Security Benchmark.

    CLI Example:

    .. code-block:: bash

        salt '*' nginx_se.run
    """
    nginx_benchmark.update({v: __grains__[k] for k, v in KEYS_MAP.iteritems() if k in __grains__ and __grains__[k]})
    nginx_benchmark['type'] = 'os'
    nginx_benchmark['benchmark'] = [
        audit1(),
        audit2(),
        audit3_2(),
        audit3_3(),
        audit3_4(),
        audit3_5(),
        audit3_6(),
        audit4(),
        audit5(),
        audit6a(),
        audit6b(),
        audit7(),
        audit8(),
        audit9(),
        audit11(),
        audit11a(),
        audit11b(),
        audit11c(),
        audit11d(),
        audit11e(),
        audit11f(),
        audit12(),
    ]
    return nginx_benchmark


def check_kernel_version():
    """ Verify version kernel"""
    _id = 'kernel_version_verify'
    configs = []
    state = PASSED
    cmd = 'uname -r'
    out = __salt__['cmd.run'](cmd).splitlines()
    configs.append(out[0])
    kernel_version = re.search(r'^(.*)/(\d+.\d+.\d+).*$', out[0], re.M | re.I).group(2)
    configs.append(kernel_version)
    kernel_3 = '.'.join(kernel_version.split('.')[:3])

    cmd = 'cat /etc/centos-release'
    out = __salt__['cmd.run'](cmd).splitlines()
    centos_version = re.search(r'^.*\.(\d+).*', out[0], re.M | re.I).group(1)
    configs.append(centos_version)
    if centos_version == '5':
        if LooseVersion(kernel_3) > LooseVersion('2.6.18.8'):
            pass
        else:
            state = FAILED
    elif centos_version == '6':
        if LooseVersion(kernel_3) > LooseVersion('2.6.32.27'):
            pass
        else:
            state = FAILED
    elif centos_version == '7':
        if LooseVersion(kernel_3) > LooseVersion('3.10.0'):
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def file_has_line(file, config):
    """ Reuse function to check if a line is in the file  """
    with open(file) as f:
        if any(re.search(r'\s*' + config + '.*', line) for line in f):
            return True
        else:
            return False


def audit1():
    """
    Verify version nginx 
    """
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    out = __salt__['nginx.version']().splitlines()
    configs.append(out[0])
    nginx_version = re.search(r'^(.*)/(\d+.\d+.\d+)$', out[0], re.M | re.I).group(2)
    configs.append(nginx_version)
    if LooseVersion(nginx_version) >= LooseVersion('1.6.3'):
        configs.append('Current nginx version >= 1.6.3 OK')
    else:
        configs.append('Current nginx version < 1.6.3 FALSE')
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit2():
    """
    Verify server has user nginx to run nginx
    """
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


def aduit3_1():
    """ Function check if nginx is hide version  """
    _id = 'nginx_verison_verify'
    configs = []
    state = PASSED
    config = 'server_tokens off;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        configs.append('Config hide version nginx is on OK')
    else:
        configs.append('Config hide version nginx is off FALSE')
    return {'id': _id, 'state': state, 'configs': configs}


def audit3_2():
    """ Disable render page frame """
    _id = 'nginx_disable_render_page_frame'
    configs = []
    state = PASSED
    config = 'add_header X-Frame-Options SAMEORIGIN;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit3_3():
    """ Disable sniffing content """
    _id = 'nginx_disable_sniffing_content'
    configs = []
    state = PASSED
    config = 'add_header X-Content-Type-Options nosniff;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit3_4():
    """ Filter XSS nginx  """
    _id = 'nginx_filter_xss'
    configs = []
    state = PASSED
    config = 'add_header X-XSS-Protection "1; mode=block";'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit3_5():
    """ Disable render page frame """
    _id = 'nginx_disable_render_page_frame'
    configs = []
    state = PASSED
    config = 'ssl_prefer_server_ciphers on;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit3_6():
    """ Enable HSTS """
    _id = 'nginx_enable_HSTS'
    configs = []
    state = PASSED
    config = 'add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit4():
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


def audit5():
    """ Verify nginx auto index is disable """
    _id = 'nginx_disable_autoindedx_verify'
    configs = []
    state = PASSED
    config = 'server_tokens off;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        configs.append('Config hide version nginx is on OK')
    else:
        configs.append('Config hide version nginx is off FALSE')
    return {'id': _id, 'state': state, 'configs': configs}


"""6a"""


def audit6a():
    """
        Verify unusable module is disable
    """
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    cmd = 'find /etc/nginx -type d -printf "%m:%f\n"'
    out = __salt__['cmd.run'](cmd).splitlines()
    permissions = []
    for line in out:
        permissions.append(line.split(":")[0])
    permissions = list(set(permissions))
    if not len(permissions) == 1:
        configs.append("folder permission has value difference to 755")
        configs.append(out)
        state = FAILED
    else:
        if permissions[0] == '755':
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
    cmd = 'find ' + nginx_upload_path + ' -type d -printf "%m:%f\n"'
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
                count += 1
    if count > 0:
        state = FAILED
    else:
        configs.append('No executable file in upload folder OK')
    return {'id': _id, 'state': state, 'configs': configs}


def audit7():
    """Verify allowed method nginx"""
    _id = 'verify allowed method nginx'
    configs = []
    state = PASSED
    with open(NGINX_CONFIG_FILE, 'r') as f:
        lines = f.read().split("\n")
    s = None
    for i, line in enumerate(lines):
        s = re.search(r'^if\s*\(\$request_method\s*!~\s*\^(\(.*)\).*$', line, re.M | re.I)
        if s:
            break
        else:
            continue
    if s:
        method_allowed = s.group(1).replace(" ", "").split("|")
        allowed_arr = ['GET', 'POST', 'HEAD']
        next_line = line[i + 1]
        if re.search(r'^.*return\s*444.*$', next_line, re.M | re.I)\
                and method_allowed.sort() == allowed_arr.sort():
            configs.append('Config allowed method is OK')
        else:
            configs.append('Configs allowed method is FAILED')
    else:
        configs.append("No configuration for allow method found.")
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit8():
    """Change error page Nginx"""
    _id = 'verify_change_error_page'
    state = PASSED
    configs = []
    pages = [400, 401, 402, 403, 404, 500, 501, 502]
    not_config_page = []
    for page in pages:
        config_line = 'error_page ' + str(page) + ' /error.html;'
        if file_has_line(NGINX_CONFIG_FILE, config_line):
            pass
        else:
            not_config_page.append(page)
    if len(not_config_page) > 0:
        configs.append('Page error ' + ', '.join(str(num) for num in not_config_page) + ' has not configured')
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit9():
    """Remove default page nginx"""
    _id = 'remove_default_page_nginx'
    state = PASSED
    configs = []
    default_pages = ['/usr/share/nginx/html/index.html']
    for page in default_pages:
        if os.path.isfile(page):
            configs.append('Default page is not removed')
            if state == PASSED:
                state = FAILED
        else:
            configs.append('Default page is removed OK')
    return {'id': _id, 'state': state, 'configs': configs}


def audit10():
    """Check if nginx load security mode"""
    _id = 'verify_security_mode_nginx'
    state = PASSED
    configs = []
    config = 'ModSecurityEnabled on;'
    if file_has_line(NGINX_CONFIG_FILE, config):
        pass
    else:
        configs.append('ModSecurity nginx is disable')
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit11():
    """Config HTTPS nginx """
    _id = 'verify_config_https'
    state = PASSED
    configs = []
    with open(NGINX_CONFIG_FILE, 'r') as f:
        lines = f.read().split("\n")
    s = None
    for i, line in enumerate(lines):
        if 'listen' in line:
            s = re.search(r'.*listen\s+443\s+ssl\s+http2\s+default_server', line, re.I | re.M)
            if s:
                break
            else:
                continue
    if s:
        configs.append('HTTPS is configured OK')
    else:
        configs.append('HTTPS is not configured FAILED')
    return {'id': _id, 'state': state, 'configs': configs}


def audit11a():
    """Config Remote Code Execution PHP """
    _id = 'verify_disable_RCE_php'
    state = PASSED
    configs = []
    require_config = 'allow_url_fopen = Off'
    if file_has_line(PHP_CONFIG_FILE, require_config):
        configs.append('Disable RCE is OK')
    else:
        state = FAILED
        configs.append('Disable RCE is FAILED')
    return {'id': _id, 'state': state, 'configs': configs}


def audit11b():
    """ Retrict access PHP folder """
    _id = 'retrict_access_php_folder'
    state = PASSED
    configs = []
    open_basedir = '/var/www/html'
    require = 'open_basedir=' + open_basedir
    cmd = 'cat ' + PHP_CONFIG_FILE + ' | grep open_basedir | grep -v "^#"'
    out = __salt__['cmd.run'](cmd).splitlines()[0]
    if 'No such file or directory' in out:
        configs.append(PHP_CONFIG_FILE + 'not found')
        state = FAILED
    else:
        if out.replace(" ", "") == require:
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit11c():
    """Disable PHP unusable function"""
    _id = 'verify_disable_unusable_function'
    state = PASSED
    configs = []
    unusable_func = ['exec', 'passthru', 'shell_exec', 'ystem', 'proc_open', 'popen', 'curl_exec',
                     'curl_multi_exec', 'parse_ini_file', 'show_source', 'symlink']
    cmd = 'cat ' + PHP_CONFIG_FILE + ' | grep disable_functions | grep -v "^#"'
    out = __salt__['cmd.run'](cmd).splitlines()[0]
    if 'No such file or directory' in out:
        configs.append(PHP_CONFIG_FILE + 'not found')
        state = FAILED
    else:
        disables = out.replace(" ", "").split("=")
        disables_modules = []
        if len(disables) > 1:
            disables_modules = disables[1].split(",")
        if set(unusable_func) < set(disables_modules):
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit11d():
    """Retrict show php error"""
    _id = 'retrict_show_php_error'
    state = PASSED
    configs = []
    cmd = 'cat ' + PHP_CONFIG_FILE + ' | grep display_errors | grep -v "^#"'
    out = __salt__['cmd.run'](cmd).splitlines()[0]
    if 'No such file or directory' in out:
        configs.append(PHP_CONFIG_FILE + 'not found')
        state = FAILED
    else:
        if out.replace(" ", "") == 'display_errors=Off':
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit11e():
    """Retrict show php info """
    _id = 'retrict_show_php_info'
    state = PASSED
    configs = []
    require = 'expose_php=Off'
    cmd = 'cat ' + PHP_CONFIG_FILE + ' | grep display_errors | grep -v "^#"'
    out = __salt__['cmd.run'](cmd).splitlines()[0]
    if 'No such file or directory' in out:
        configs.append(PHP_CONFIG_FILE + 'not found')
        state = FAILED
    else:
        if out.replace(" ", "") == require:
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit11f():
    """Secure mode for SQL """
    _id = 'config_secure_mode_sql'
    state = PASSED
    configs = []
    require = 'sql.safe_mode=On'
    cmd = 'cat ' + PHP_CONFIG_FILE + ' | grep sql.safe_mode | grep -v "^#"'
    out = __salt__['cmd.run'](cmd).splitlines()[0]
    if 'No such file or directory' in out:
        configs.append(PHP_CONFIG_FILE + 'not found')
        state = FAILED
    else:
        if out.replace(" ", "") == require:
            pass
        else:
            state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}


def audit12():
    """ Verify Log configuration of Nginx"""
    _id = 'verify_log_configuration'
    state = PASSED
    configs = []
    cmd = 'cat ' + NGINX_CONFIG_FILE + ' | grep log_format | grep -v "^#"'
    log_format = __salt__['cmd.run'](cmd).splitlines()
    cmd = 'cat ' + NGINX_CONFIG_FILE + ' | grep access_log | grep -v "^#"'
    access_log = __salt__['cmd.run'](cmd).splitlines()
    if len(log_format) > 0 and len(access_log) > 0 and\
        re.search(r'\s*log_format\s+main\s+.*;', log_format[0]) and\
            re.search(r'\s*access_log\s+main.*', access_log[0]):
        pass
    else:
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}

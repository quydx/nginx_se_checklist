
def check_os_version():
    """ Verify version nginx """
    _id = 'nginx_version_verify'
    configs = []
    state = PASSED
    cmd = 'uname -r'
    out = __salt__['cmd.run']().splitlines()
    configs.append(out[0])
    kernel_version = re.search(r'^(.*)/(\d+.\d+.\d+).*$', out[0], re.M | re.I).group(2)
    configs.append(nginx_version)
    if LooseVersion(nginx_version) >= LooseVersion('1.6.3'):
        configs.append('Current nginx version >= 1.6.3 OK')
    else:
        configs.append('Current nginx version < 1.6.3 FALSE')
        state = FAILED
    return {'id': _id, 'state': state, 'configs': configs}

# -*- coding: utf-8 -*-
'''
Nginx Security Benchmark module
'''

import re	
import logging
import pwd
from salt import utils 

__virtualname__ = 'nginx_se'
__outputter__ = {'run': 'nested'}

GREP = 

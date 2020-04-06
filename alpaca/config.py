"""
Parse the config.json
"""
import os
import json

DEFAULT_MTU = 1408

def _get_conf_dir(path: str = None):

    if path:
        conf_dir = os.path.dirname(path)
        return conf_dir

    cur_dir = os.path.dirname(os.path.realpath(__file__))

    if cur_dir.startswith('/usr/local/bin'):
        parent = '/usr/local/etc'
    elif cur_dir.startswith('/usr/bin'):
        parent = '/etc'
    else:
        parent = os.path.dirname(cur_dir)

    conf_dir = os.path.join(parent, 'alpaca-tunnel.d')

    return conf_dir


class Config:
    DEFAULT_CONFIG = 'config.json'
    DEFAULT_SECRET = 'secrets.txt'

    def __init__(self, path: str = None):
        if not path:
            path = os.path.join(_get_conf_dir(), self.DEFAULT_CONFIG)
        self.path = path

        self.name    : str  = None
        self.mode    : str  = None
        self.group   : str  = None
        self.net     : str  = None
        self.id      : str  = None
        self.gateway : str  = None
        self.port    : str  = None
        self.mtu     : str  = None
        self.secret_file  : str  = None
        self.log_level    : str  = None

        self._parse_json()

    def __repr__(self):
        result = '\n'
        for field in ('name', 'mode', 'group', 'net', 'id', 'gateway', 'port', 'mtu', 'secret_file'):
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value}\n'
        return result

    def _parse_json(self):

        with open(self.path) as f:
            conf = json.load(f)

        self.name = conf['name']
        self.mode = conf['mode']
        self.group = conf['group']
        self.net = conf['net']
        self.id = conf['id']
        self.gateway = conf.get('gateway')
        self.port = conf.get('port', 0)
        self.mtu = conf.get('mtu', DEFAULT_MTU)

        self.secret_file = os.path.join(
            _get_conf_dir(self.path),
            conf.get('secret_file', self.DEFAULT_SECRET))

        self.log_level = conf.get('log_level', 'info').upper()
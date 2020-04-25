"""
Parse the config.json
"""
from typing import List, Dict
import os
import json

from .common import id_pton

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
        self.virtual_net  : str  = None
        self.secret_file  : str  = None
        self.log_level    : str  = None
        self.inactive_downward_static: bool = False
        self.forwarders     : List[int] = []
        self.post_up_cmds   : List[str] = []
        self.post_down_cmds : List[str] = []
        self.local_routes   : List[str] = []
        self.chnroute       : Dict = {}

        self._parse_json()
        self._validate()

    def __repr__(self):
        result = '\n'
        for field in ('name', 'mode', 'group', 'net', 'id', 'gateway',
                      'port', 'mtu', 'forwarders', 'secret_file'):
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
        self.virtual_net = conf.get('virtual_net')
        self.id = conf['id']
        self.gateway = conf.get('gateway')
        self.inactive_downward_static = conf.get('inactive_downward_static', False)
        self.port = conf.get('port', 0)
        self.mtu = conf.get('mtu', DEFAULT_MTU)
        self.post_up_cmds = conf.get('post_up_cmds', [])
        self.post_down_cmds = conf.get('post_down_cmds', [])
        self.local_routes = conf.get('local_routes', [])

        if conf.get('forwarders'):
            for id_str in conf.get('forwarders'):
                if id_pton(id_str) != id_pton(self.id):
                    self.forwarders.append(id_pton(id_str))

        self.secret_file = os.path.join(
            _get_conf_dir(self.path),
            conf.get('secret_file', self.DEFAULT_SECRET))

        if conf.get('chnroute'):
            self.chnroute = conf.get('chnroute')
            self.chnroute['data'] = os.path.join(
                _get_conf_dir(self.path),
                conf.get('chnroute')['data'])

        self.log_level = conf.get('log_level', 'info').upper()

    def _validate(self):
        assert self.mode in ('server', 'client', 'forwarder')

        if self.mode == 'client':
            assert self.gateway

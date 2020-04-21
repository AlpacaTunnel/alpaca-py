import re
import time
import logging

from .common import exec_cmd, ip_ntop
from .config import Config
from .peer import PeerPool

logger = logging.getLogger(__name__)


class System:
    def __init__(self, conf: Config, peers: PeerPool):
        self.conf = conf
        self.peers = peers
        self.default_route: str = None
        self.gateway = f'{self.conf.net}.{self.conf.gateway}'

    def _cmd(self, c, strict=True) -> str:
        rc, output = exec_cmd(c)
        if strict and int(rc) != 0:
            err = f'cmd ({c}) error: {output}'
            logger.error(err)
            raise Exception(err)
        return output

    def _add_routes_cmds(self):
        """
        1) delete default route in main table
        2) add routes to servers in default table
        3) add default to gateway in default table
        """
        cmds = ['ip route delete default']

        for peer in self.peers.pool.values():
            for addr in peer.get_addrs(static=True):
                ip = ip_ntop(addr.ip)
                cmds.append(f'ip route add {ip} via {self.default_route} table default')

        cmds.append(f'ip route add default via {self.gateway} table default')
        return cmds

    def _del_routes_cmds(self):
        """
        reverse _add_routes_cmds()
        """
        cmds = [f'ip route add default via {self.default_route}']

        for peer in self.peers.pool.values():
            for addr in peer.get_addrs(static=True):
                ip = ip_ntop(addr.ip)
                cmds.append(f'ip route delete {ip} via {self.default_route} table default')

        cmds.append(f'ip route delete default table default')
        return cmds

    def _get_default_route(self):
        route = self._cmd('ip route')
        re_obj = re.search(r'default via\s([\.\d]+)\s', route)
        if not re_obj:
            return None
        return re_obj.group(1)

    def _wait_default_route(self):
        while not self._get_default_route():
            logger.debug('No default route yet, wait 1s and try again...')
            time.sleep(1)
        self.default_route = self._get_default_route()

    def init(self):
        self._wait_default_route()

        for cmd in self._add_routes_cmds():
            self._cmd(cmd)

    def restore(self):
        for cmd in self._del_routes_cmds():
            self._cmd(cmd, strict=False)

import re
import time
import logging
import signal
import socket

from .common import exec_cmd, ip_ntop
from .config import Config
from .peer import PeerPool
from .vpn import VPN

logger = logging.getLogger(__name__)

TCP_MSS = 1300


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

    def _init_client(self):
        self._wait_default_route()

        cmds = self._add_routes_cmds()
        cmds += [
            'sysctl net.ipv4.ip_forward=1',
            f'iptables -A FORWARD -s {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -A FORWARD -d {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {TCP_MSS}',
        ]
        for cmd in cmds:
            self._cmd(cmd)

    def _restore_client(self):
        cmds = self._del_routes_cmds()
        cmds += [
            f'iptables -D FORWARD -s {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -D FORWARD -d {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {TCP_MSS}',
        ]
        for cmd in cmds:
            self._cmd(cmd, strict=False)

    def _init_server(self):
        cmds = [
            'sysctl net.ipv4.ip_forward=1',
            f'iptables -A FORWARD -s {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -A FORWARD -d {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {TCP_MSS}',
            f'iptables -A POSTROUTING -t nat -s {self.conf.net}.0.0/16 -j MASQUERADE',
        ]
        for cmd in cmds:
            self._cmd(cmd)

    def _restore_server(self):
        cmds = [
            f'iptables -D FORWARD -s {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -D FORWARD -d {self.conf.net}.0.0/16 -j ACCEPT',
            f'iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {TCP_MSS}',
            f'iptables -D POSTROUTING -t nat -s {self.conf.net}.0.0/16 -j MASQUERADE',
        ]
        for cmd in cmds:
            self._cmd(cmd, strict=False)

    def _send_pkt_to_self(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        sock.sendto(b'0', ('0.0.0.0', self.conf.port))

    def init(self):
        if self.conf.mode == 'client':
            self._init_client()
        else:
            self._init_server()

    def restore(self):
        if self.conf.mode == 'client':
            self._restore_client()
        else:
            self._restore_server()

        # quick fix: remove the tuntap and send pkt to self to end worker_recv
        self._cmd(f'ip link del {self.conf.name}', strict=False)
        self._send_pkt_to_self()


def signal_handler(sig, frame):
    logger.info('signal recived: %s', sig)
    global SYSTEM_INSTANCE, VPN_INSTANCE
    # avoid dup restore routes
    if VPN_INSTANCE.running.value:
        SYSTEM_INSTANCE.restore()
    VPN_INSTANCE.running.value = 0


def install_signal_restore(sys: System, vpn: VPN):
    global SYSTEM_INSTANCE, VPN_INSTANCE
    SYSTEM_INSTANCE = sys
    VPN_INSTANCE = vpn

    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

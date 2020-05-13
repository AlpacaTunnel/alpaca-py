"""
VPN Context.
"""
from typing import List
import time
from Crypto.Cipher import AES
from multiprocessing import Value

from .common import truncate_key, id_pton
from .config import Config
from .peer import PeerPool, PeerAddr


class VPN:
    MAGIC = 8964
    NETMASK = 0xffff0000
    IDMASK = 0x0000ffff

    # TODO: if spawn multiple processes to run this class, should sync these two variables
    SEQUENCE = 0
    TIMESTAMP = 0

    def __init__(self, config: Config, peers: PeerPool):
        self.config = config
        self.group_cipher = AES.new(truncate_key(config.group), AES.MODE_ECB)
        self.peers = peers

        self.running = Value('i', 1)  # use an integer to indicate running or not

        ip_a, ip_b = config.net.split('.')
        self.network: int = (int(ip_a) << 24) + (int(ip_b) << 16)
        self.id = id_pton(config.id)
        if config.gateway:
            self.gateway = id_pton(config.gateway)
        else:
            self.gateway = 0

        self.do_nat = False
        self.virtual_net = 0
        if config.virtual_net and config.virtual_net != config.net:
            self.do_nat = True
            ip_a, ip_b = config.virtual_net.split('.')
            self.virtual_net = (int(ip_a) << 24) + (int(ip_b) << 16)

    def __repr__(self):
        return f'network: {self.config.net}, id: {self.id}'

    def update_timestamp_seq(self):
        now = int(time.time())
        if now == self.TIMESTAMP:
            self.SEQUENCE += 1
        else:
            self.TIMESTAMP = now
            self.SEQUENCE = 0

    def get_dst_addrs(self, src_id: int, dst_id: int) -> List[PeerAddr]:
        # 1) From server to client, don't send to forwarder (configured on current host).
        #    If client has static address, will send to both static and dynamical.
        if src_id < dst_id:
            return self.peers.pool[dst_id].get_addrs(
                inactive_downward_static=self.config.inactive_downward_static)

        # 2) followings are from client to server
        #    Servers must have static addresses, so only send to static.

        if not self.config.forwarders:
            return self.peers.pool[dst_id].get_addrs(static=True)

        dst_addrs = []
        for forwarder_id in self.config.forwarders:
            dst_addrs += self.peers.pool[forwarder_id].get_addrs(static=True)

        return dst_addrs

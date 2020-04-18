"""
VPN Context.
"""
import time
from Crypto.Cipher import AES

from .common import truncate_key, id_pton
from .config import Config
from .peer import PeerPool


class VPN:
    MAGIC = 1990
    NETMASK = 0xffff0000
    IDMASK = 0x0000ffff

    # TODO: if spawn multiple processes to run this class, should sync these two variables
    SEQUENCE = 0
    TIMESTAMP = 0

    def __init__(self, config: Config, peers: PeerPool):
        self.config = config
        self.group_cipher = AES.new(truncate_key(config.group), AES.MODE_ECB)
        self.peers = peers

        ip_a, ip_b = config.net.split('.')
        self.network = (int(ip_a) << 24) + (int(ip_b) << 16)
        self.id = id_pton(config.id)

    def __repr__(self):
        return f'network: {self.config.net}, id: {self.id}'

    def update_timestamp_seq(self):
        now = int(time.time()) & 0x000fffff
        if now == self.TIMESTAMP:
            self.SEQUENCE += 1
        else:
            self.TIMESTAMP = now
            self.SEQUENCE = 0

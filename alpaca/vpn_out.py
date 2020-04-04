"""
Read packet from tunif, encrypt and send to socket.
"""
from typing import Tuple, Iterable
import logging
import time
import os
import random
from Crypto.Cipher import AES

from .common import truncate_key
from .config import Config
from .peer import PeerPool, PeerAddr
from .header import Header
from .ip_packet import IPPacket
# from .ip_packet_bytearray import IPPacket

logger = logging.getLogger(__name__)


class VPNOut:
    MAGIC = 1990
    NETMASK = 0xffff0000
    IDMASK = 0x0000ffff

    # TODO: if spawn multiple processes to run this VPNOut class, should sync these two variables
    SEQUENCE = 0
    TIMESTAMP = 0

    def __init__(self, config: Config, peers: PeerPool):
        self.group_cipher = AES.new(truncate_key(config.group), AES.MODE_ECB)
        self.peers = peers

        ip_a, ip_b = config.net.split('.')
        self.network = (int(ip_a) << 24) + (int(ip_b) << 16)
        self.id = int(config.id.split('.')[0]) * 256 + int(config.id.split('.')[1])

    def _update_timestamp_seq(self):
        now = int(time.time()) & 0x000fffff
        if now == self.TIMESTAMP:
            self.SEQUENCE += 1
        else:
            self.TIMESTAMP = now
            self.SEQUENCE = 0

    @staticmethod
    def _encrypt_body(header: Header, psk: bytes, body: bytes) -> bytes:
        aes_block_length = ((header.length + 15) // 16) * 16
        padding = os.urandom(aes_block_length - header.length)

        cipher = AES.new(psk, AES.MODE_CBC, header.get_iv())
        return cipher.encrypt(body + padding)

    @staticmethod
    def _encrypt_header(header: Header, psk: bytes):
        cipher = AES.new(psk, AES.MODE_ECB)
        return cipher.encrypt(header.to_network())

    def _fill_header(self, body: bytes) -> Tuple[Header, bytes]:
        ip = IPPacket().from_network(body)

        ip_h = ip.header
        # logger.debug(ip_h)
        # logger.debug(f'L4 INFO: {ip.l4_header}')

        if ip_h.version != 4:
            logger.warning(f'not support version: {ip_h.version}')
            return None, body

        h = Header()
        h.length = len(body)
        h.ttl = 15

        h.src_id = self.id

        if (self.network & self.NETMASK) == (ip_h.src_ip & self.NETMASK):
            h.src_in = 1
            ip.snat(h.src_id)
        else:
            h.src_in = 0

        if (self.network & self.NETMASK) == (ip_h.dst_ip & self.NETMASK):
            h.dst_in = 1
            h.dst_id = ip_h.dst_ip & self.IDMASK
            ip.dnat(h.dst_id)
        else:
            h.dst_in = 0
            # TODO: get dst_id from local route
            h.dst_id = 0
            logger.warning('should get dst_id from local route')
            return None, body

        # logger.debug(ip_h)
        # logger.debug(f'L4 INFO: {ip.l4_header}')

        h.magic = self.MAGIC

        self._update_timestamp_seq()
        h.timestamp = self.TIMESTAMP
        h.sequence = self.SEQUENCE
        h.padding = random.randint(0, 4000)

        # logger.debug(h)
        return h, ip.to_network()

    def get_outter_packet(self, body: bytes) -> Tuple[Iterable[PeerAddr], bytes]:
        h, body = self._fill_header(body)
        if not h:
            return None, None

        header_plain = h.to_network()
        header_cipher = self.group_cipher.encrypt(header_plain)

        bigger_id = max(h.src_id, h.dst_id)
        psk = self.peers.pool[bigger_id].psk

        icv = self._encrypt_header(h, psk)

        body_cipher = self._encrypt_body(h, psk, body)

        return self.peers.pool[h.dst_id].get_addrs(), b''.join([header_cipher, icv, body_cipher])

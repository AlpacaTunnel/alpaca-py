"""
Read packet from tunif, encrypt and send to socket.
"""
from typing import Tuple, List
import logging
import time
import os
import random
from Crypto.Cipher import AES

from .vpn import VPN
from .peer import PeerAddr
from .header import Header
from .ip_packet import IPPacket
# from .ip_packet_bytearray import IPPacket

logger = logging.getLogger(__name__)


class PktOut:
    def __init__(self, vpn: VPN, body: bytes):
        self.vpn = vpn
        self.body = body

        self.header = Header()
        self.outter_pkt: bytes = None
        self.dst_addrs: List[PeerAddr] = None
        self.valid = True

        self._fill_header()
        self._fill_outter_pkt()
        self._fill_dst_addrs()

    def _encrypt_body(self, header: Header, psk: bytes) -> bytes:
        aes_block_length = ((header.length + 15) // 16) * 16
        padding = os.urandom(aes_block_length - header.length)

        cipher = AES.new(psk, AES.MODE_CBC, header.get_iv())
        return cipher.encrypt(self.body + padding)

    @staticmethod
    def _encrypt_header(header: Header, psk: bytes):
        cipher = AES.new(psk, AES.MODE_ECB)
        return cipher.encrypt(header.to_network())

    def _fill_header(self) -> bool:
        body = self.body
        ip = IPPacket().from_network(body)
        logger.debug(ip)

        ip_h = ip.header

        if ip_h.version != 4:
            logger.debug(f'not support version: {ip_h.version}')
            self.valid = False
            return

        h = self.header
        h.length = len(body)
        h.ttl = 15

        h.src_id = self.vpn.id

        if (self.vpn.network & self.vpn.NETMASK) == (ip_h.src_ip & self.vpn.NETMASK):
            h.src_in = 1
            ip.snat(h.src_id)
        else:
            h.src_in = 0

        if (self.vpn.network & self.vpn.NETMASK) == (ip_h.dst_ip & self.vpn.NETMASK):
            h.dst_in = 1
            h.dst_id = ip_h.dst_ip & self.vpn.IDMASK
            ip.dnat(h.dst_id)
        else:
            h.dst_in = 0
            # TODO: get dst_id from local route
            h.dst_id = 0
            raise Exception('should get dst_id from local route')

        # body changed after nat
        self.body = ip.to_network()

        logger.debug(ip)

        h.magic = self.vpn.MAGIC

        self.vpn.update_timestamp_seq()
        h.timestamp = self.vpn.TIMESTAMP
        h.sequence = self.vpn.SEQUENCE
        h.padding = random.randint(0, 4000)

        logger.debug(h)

    def _fill_outter_pkt(self):
        if not self.valid:
            return

        h = self.header

        header_plain = h.to_network()
        header_cipher = self.vpn.group_cipher.encrypt(header_plain)

        bigger_id = max(h.src_id, h.dst_id)
        psk = self.vpn.peers.pool[bigger_id].psk

        icv = self._encrypt_header(h, psk)
        body_cipher = self._encrypt_body(h, psk)

        self.outter_pkt = b''.join([header_cipher, icv, body_cipher])

    def _fill_dst_addrs(self):
        if not self.valid:
            return

        dst_addrs = []
        if self.header.dst_id < self.header.src_id and self.vpn.config.forwarders:
            for forwarder_id in self.vpn.config.forwarders:
                dst_addrs += self.vpn.peers.pool[forwarder_id].get_addrs(static=True)
        else:
            dst_addrs += self.vpn.peers.pool[self.header.dst_id].get_addrs()

        self.dst_addrs = dst_addrs
        logger.debug(self.dst_addrs)
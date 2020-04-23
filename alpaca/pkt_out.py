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

        self._process()

    def _process(self):
        self._fill_header()
        if not self.valid:
            return

        self._fill_outter_pkt()
        self._fill_dst_addrs()

    def _encrypt_body(self, header: Header, psk: bytes) -> bytes:
        aes_block_length = ((header.length + 15) // 16) * 16
        padding = os.urandom(aes_block_length - header.length)

        cipher = AES.new(psk, AES.MODE_CBC, header.get_iv())
        return cipher.encrypt(self.body + padding)

    def _get_icv(self, psk: bytes):
        cipher = AES.new(psk, AES.MODE_ECB)
        return cipher.encrypt(self.header.to_network())

    def _fill_header(self):
        body = self.body
        ip = IPPacket().from_network(body)
        logger.debug(ip)

        ip_h = ip.header

        if ip_h.version != 4:
            logger.debug('not support version: %s', ip_h.version)
            self.valid = False
            return

        h = self.header
        h.length = len(body)
        h.ttl = 15

        h.src_id = self.vpn.id

        # TODO: src_in/dst_in can be removed, because NATed address can tell
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
            # TODO: currently, only use gateway as dst_id. Should get dst_id from local route.
            h.dst_id = self.vpn.gateway

        if h.dst_id == 0:
            logger.debug('no dst id to send')
            self.valid = False
            return

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
        h = self.header
        header_cipher = self.vpn.group_cipher.encrypt(h.to_network())

        bigger_id = max(h.src_id, h.dst_id)
        psk = self.vpn.peers.pool[bigger_id].psk

        icv = self._get_icv(psk)
        body_cipher = self._encrypt_body(h, psk)

        if h.length > 500:
            padding = b''
        else:
            padding = os.urandom(random.randint(250, 800))

        self.outter_pkt = b''.join([header_cipher, icv, body_cipher, padding])

    def _fill_dst_addrs(self):
        self.dst_addrs = self.vpn.get_dst_addrs(self.header.src_id, self.header.dst_id)
        logger.debug('(%s -> %s): %s', self.header.src_id, self.header.dst_id, self.dst_addrs)

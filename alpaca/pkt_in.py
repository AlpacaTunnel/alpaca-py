"""
Receive packet from socket, decrypt and write to tunif.
"""
from typing import Iterable
import logging
from Crypto.Cipher import AES

from .vpn import VPN
from .peer import PeerAddr
from .header import Header, HEADER_LENGTH

logger = logging.getLogger(__name__)


class PktIn:
    ACTION_WRITE = 0
    ACTION_FORWARD = 1
    def __init__(self, vpn: VPN, outter_pkt: bytes, addr: PeerAddr):
        self.vpn = vpn
        self.outter_pkt = outter_pkt
        self.addr = addr
        self.peers = self.vpn.peers

        self.action = self.ACTION_WRITE
        self.valid = True

        self.header = Header()
        self.psk: bytes = None
        self.body: bytes = None
        self.new_outter_pkt: bytes = None
        self.dst_addrs: Iterable[PeerAddr] = None

        self._process()

    def _process(self):
        header_plain = self.vpn.group_cipher.decrypt(self.outter_pkt[0: HEADER_LENGTH])
        self.header.from_network(header_plain)
        logger.debug(self.header)

        if not self._is_header_valid():
            self.valid = False
            return

        logger.debug('store addr of %s: %s', self.header.src_id, self.addr)
        self.peers.pool[self.header.src_id].add_addr(self.addr)

        if not self._is_pkt_valid():
            self.valid = False
            return

        if self.header.dst_id == self.vpn.id:
            self.action = self.ACTION_WRITE
            self.body = self._decrypt_body()
        else:
            self.action = self.ACTION_FORWARD
            self.new_outter_pkt = self.outter_pkt
            self.dst_addrs = self._get_dst_addrs()

    def _decrypt_body(self) -> bytes:
        bigger_id = max(self.header.src_id, self.header.dst_id)
        psk = self.vpn.peers.pool[bigger_id].psk
        aes_block_length = ((self.header.length + 15) // 16) * 16
        cipher = AES.new(psk, AES.MODE_CBC, self.header.to_network())
        return cipher.decrypt(self.outter_pkt[HEADER_LENGTH: HEADER_LENGTH + aes_block_length])

    def _get_dst_addrs(self):
        dst_addrs = self.vpn.get_dst_addrs(self.header.src_id, self.header.dst_id)
        for addr in dst_addrs:
            if addr.ip != self.addr.ip:  # split horizon
                logger.debug('(%s -> %s): %s', self.header.src_id, self.header.dst_id, addr)
                yield addr

    def _is_header_valid(self) -> bool:
        h = self.header
        if h.magic != self.vpn.MAGIC:
            logger.debug('Invalid magic, ignore the packet.')
            return False

        if not self.peers.pool.get(h.src_id) or not self.peers.pool.get(h.dst_id):
            logger.debug('Not found srd_id or dst_id: (%s -> %s)', h.src_id, h.dst_id)
            return False

        if h.src_id == h.dst_id:
            logger.debug('The same srd_id and dst_id: (%s -> %s)', h.src_id, h.dst_id)
            return False

        return True

    def _is_pkt_valid(self) -> bool:
        h = self.header
        self.peers.pool[h.src_id].init_pkt_filter()

        if not self.peers.pool[h.src_id].pkt_filter.is_valid(h.timestamp, h.sequence):
            logger.debug('Packet is filtered as invalid, drop it: (%s -> %s)', h.src_id, h.dst_id)
            return False

        return True

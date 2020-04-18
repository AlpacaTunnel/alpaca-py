"""
Receive packet from socket, decrypt and write to tunif.
"""
from typing import List
import logging
from Crypto.Cipher import AES

from .vpn import VPN
from .peer import PeerAddr
from .header import Header, HEADER_LENGTH, ICV_LENGTH
from .ip_packet import IPPacket
# from .ip_packet_bytearray import IPPacket

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
        self.dst_addrs: List[PeerAddr] = None

        self._process()

    def _process(self):
        self._get_header()

        if not self._is_header_valid():
            self.valid = False
            return

        bigger_id = max(self.header.src_id, self.header.dst_id)
        self.psk = self.peers.pool[bigger_id].psk

        if not self._is_icv_valid():
            self.valid = False
            return

        self._store_peer_addr()

        if self._is_pkt_dup():
            self.valid = False
            return

        if self.header.dst_id == self.vpn.id:
            self.action = self.ACTION_WRITE
            self._get_body()
        else:
            self.action = self.ACTION_FORWARD
            self._process_forward()

    def _process_forward(self):
        h = self.header
        if h.ttl == 0:
            logger.debug('TTL expired')
            self.valid = False
            return

        # 2 bits, max value is 3
        h.pi_b = min(h.pi_b + 1, 3)
        h.ttl -= 1

        header_cipher = self.vpn.group_cipher.encrypt(h.to_network())
        icv = self._get_icv()
        body_cipher = self.outter_pkt[HEADER_LENGTH+ICV_LENGTH:]

        self.new_outter_pkt = b''.join([header_cipher, icv, body_cipher])

        self.dst_addrs = self.vpn.get_dst_addrs(self.header.src_id, self.header.dst_id)
        logger.debug(self.dst_addrs)

    def _decrypt_body(self) -> bytes:
        aes_block_length = ((self.header.length + 15) // 16) * 16
        cipher = AES.new(self.psk, AES.MODE_CBC, self.header.get_iv())
        return cipher.decrypt(self.outter_pkt[HEADER_LENGTH+ICV_LENGTH: HEADER_LENGTH+ICV_LENGTH + aes_block_length])

    def _get_icv(self):
        cipher = AES.new(self.psk, AES.MODE_ECB)
        return cipher.encrypt(self.header.to_network())

    def _is_header_valid(self) -> bool:
        h = self.header
        if h.magic != self.vpn.MAGIC:
            logger.debug('Invalid magic, ignore the packet.')
            return False

        if not self.peers.pool.get(h.src_id) or not self.peers.pool.get(h.dst_id):
            logger.debug(f'Not found srd_id or dst_id: {h.src_id} -> {h.dst_id}')
            return False

        if h.src_id == h.dst_id:
            logger.debug(f'Invalid srd_id or dst_id: {h.src_id} -> {h.dst_id}')
            return False

        return True

    def _is_pkt_dup(self) -> bool:
        h = self.header
        self.peers.pool[h.src_id].init_pkt_filter()

        if self.peers.pool[h.src_id].pkt_filter.is_dup(h.timestamp, h.sequence):
            logger.debug('Packet is duplicated, drop it')
            return True

        return False

    def _get_header(self):
        header_cipher = self.outter_pkt[0:HEADER_LENGTH]
        header_plain = self.vpn.group_cipher.decrypt(header_cipher)
        self.header.from_network(header_plain)
        logger.debug(self.header)

    def _is_icv_valid(self) -> bool:
        icv = self._get_icv()
        if icv != self.outter_pkt[HEADER_LENGTH: HEADER_LENGTH+ICV_LENGTH]:
            logger.debug('icv not match')
            return False

        return True

    def _store_peer_addr(self):
        logger.debug(self.addr)
        self.peers.pool[self.header.src_id].add_addr(self.addr)

    def _get_body(self):
        body = self._decrypt_body()
        ip = IPPacket().from_network(body)
        logger.debug(ip)

        if ip.header.version != 4:
            logger.debug(f'not support version: {ip.header.version}')
            self.valid = False
            return

        h = self.header
        if h.dst_in:
            new_ip = self.vpn.network + h.dst_id
            ip.dnat(new_ip)

        if h.src_in:
            new_ip = self.vpn.network + h.src_id
            ip.snat(new_ip)

        logger.debug(ip)
        self.body = ip.to_network()

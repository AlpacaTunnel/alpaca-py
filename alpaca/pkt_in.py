"""
Receive packet from socket, decrypt and write to tunif.
"""
import logging
from Crypto.Cipher import AES

from .vpn import VPN
from .peer import PeerAddr
from .header import Header, HEADER_LENGTH, ICV_LENGTH
from .ip_packet import IPPacket
# from .ip_packet_bytearray import IPPacket

logger = logging.getLogger(__name__)


class PktIn:
    MAGIC = 1990
    def __init__(self, vpn: VPN, outter_pkt: bytes, addr: PeerAddr):
        self.vpn = vpn
        self.outter_pkt = outter_pkt
        self.addr = addr
        self.peers = self.vpn.peers

        self.header = Header()
        self.body: bytes = None
        self.valid = True

        self._get_header()
        self._validate_header()
        self._validate_icv()
        self._get_body()
        self._store_dst_addr()

    def _decrypt_body(self) -> bytes:
        bigger_id = max(self.header.src_id, self.header.dst_id)
        psk = self.peers.pool[bigger_id].psk

        aes_block_length = ((self.header.length + 15) // 16) * 16
        cipher = AES.new(psk, AES.MODE_CBC, self.header.get_iv())
        return cipher.decrypt(self.outter_pkt[HEADER_LENGTH+ICV_LENGTH : HEADER_LENGTH+ICV_LENGTH+aes_block_length])

    def _encrypt_header(self, psk: bytes):
        cipher = AES.new(psk, AES.MODE_ECB)
        return cipher.encrypt(self.header.to_network())

    def _validate_header(self):
        h = self.header
        if h.magic != self.MAGIC:
            logger.debug('Invalid magic, ignore the packet.')
            self.valid = False
            return

        if not self.peers.pool.get(h.src_id) or not self.peers.pool.get(h.dst_id):
            logger.debug(f'Invalid srd_id or dst_id: {h.src_id} -> {h.dst_id}')
            self.valid = False
            return

        self.peers.pool[h.src_id].init_pkt_marker()
        if self.peers.pool[h.src_id].pkt_marker.is_dup(h.timestamp, h.sequence):
            logger.debug('Packet is duplicated, drop it')
            self.valid = False
            return

    def _get_header(self):
        header_cipher = self.outter_pkt[0:HEADER_LENGTH]
        header_plain = self.vpn.group_cipher.decrypt(header_cipher)
        self.header.from_network(header_plain)
        logger.debug(self.header)

    def _validate_icv(self):
        if not self.valid:
            return

        bigger_id = max(self.header.src_id, self.header.dst_id)
        psk = self.peers.pool[bigger_id].psk

        icv = self._encrypt_header(psk)
        if icv != self.outter_pkt[HEADER_LENGTH: HEADER_LENGTH+ICV_LENGTH]:
            logger.debug('icv not match')
            self.valid = False

    def _store_dst_addr(self):
        if not self.valid:
            return

        logger.debug(self.addr)
        self.peers.pool[self.header.src_id].add_addr(self.addr)

    def _get_body(self):
        if not self.valid:
            return

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

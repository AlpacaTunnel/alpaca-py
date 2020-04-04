"""
Receive packet from socket, decrypt and write to tunif.
"""
import logging
from Crypto.Cipher import AES

from .common import truncate_key
from .config import Config
from .peer import PeerPool, PeerAddr
from .header import Header, HEADER_LENGTH, ICV_LENGTH
from .ip_packet import IPPacket
# from .ip_packet_bytearray import IPPacket

logger = logging.getLogger(__name__)


class VPNIn:
    MAGIC = 1990
    def __init__(self, config: Config, peers: PeerPool):
        self.group_cipher = AES.new(truncate_key(config.group), AES.MODE_ECB)
        self.peers = peers
        net_a, net_b = config.net.split('.')
        self.net = (int(net_a) << 24) + (int(net_b) << 16)

    @staticmethod
    def _decrypt_body(header: Header, psk: bytes, packet: bytes) -> bytes:
        aes_block_length = ((header.length + 15) // 16) * 16
        cipher = AES.new(psk, AES.MODE_CBC, header.get_iv())
        return cipher.decrypt(packet[HEADER_LENGTH+ICV_LENGTH : HEADER_LENGTH+ICV_LENGTH+aes_block_length])

    @staticmethod
    def _encrypt_header(header: Header, psk: bytes):
        cipher = AES.new(psk, AES.MODE_ECB)
        return cipher.encrypt(header.to_network())

    def get_inner_packet(self, packet: bytes, addr: PeerAddr) -> bytes:
        header_cipher = packet[0:HEADER_LENGTH]
        header_plain = self.group_cipher.decrypt(header_cipher)

        h = Header()
        h.from_network(header_plain)

        # logger.debug(h)

        if h.magic != self.MAGIC:
            return None

        self.peers.pool[h.src_id].add_addr(addr)

        bigger_id = max(h.src_id, h.dst_id)

        psk = self.peers.pool[bigger_id].psk

        icv = self._encrypt_header(h, psk)
        if icv != packet[HEADER_LENGTH: HEADER_LENGTH+ICV_LENGTH]:
            logger.warning('icv not match')
            return None

        body = self._decrypt_body(h, psk, packet)

        ip = IPPacket().from_network(body)

        ip_h = ip.header
        # logger.debug(ip_h)
        # logger.debug(f'L4 INFO: {ip.l4_header}')

        if ip_h.version != 4:
            logger.error(f'not support version: {ip_h.version}')
            return None

        if h.dst_in:
            new_ip = self.net + h.dst_id
            ip.dnat(new_ip)

        if h.src_in:
            new_ip = self.net + h.src_id
            ip.snat(new_ip)

        # logger.debug(ip_h)
        # logger.debug(f'L4 INFO: {ip.l4_header}')

        return ip.to_network()

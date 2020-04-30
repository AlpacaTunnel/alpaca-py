"""
Read packet from tunif, encrypt and send to socket.
"""
from typing import List
import logging
import os
import random

from .vpn import VPN
from .peer import PeerAddr
from .header import Header
from .ip_packet import IPHeader

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

    def _fill_header(self):
        ip_h = IPHeader().from_network(self.body[0: IPHeader.LENGTH])

        if ip_h.version != 4:
            logger.debug('not support version: %s', ip_h.version)
            self.valid = False
            return

        h = self.header
        h.length = len(self.body)
        h.magic = self.vpn.MAGIC

        h.src_id = self.vpn.id
        if self.vpn.network == (ip_h.dst_ip & self.vpn.NETMASK):
            h.dst_id = ip_h.dst_ip & self.vpn.IDMASK
        else:
            h.dst_id = self.vpn.gateway

        self.vpn.update_timestamp_seq()
        h.timestamp = self.vpn.TIMESTAMP
        h.sequence = self.vpn.SEQUENCE

        logger.debug(h)

    def _fill_outter_pkt(self):
        if self.header.length > 500:
            padding = b''
        else:
            padding = os.urandom(random.randint(250, 800))

        self.outter_pkt = b''.join([self.header.to_network(), self.body, padding])

    def _fill_dst_addrs(self):
        self.dst_addrs = self.vpn.get_dst_addrs(self.header.src_id, self.header.dst_id)
        logger.debug('(%s -> %s): %s', self.header.src_id, self.header.dst_id, self.dst_addrs)

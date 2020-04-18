"""
Handle IP packet, include IP header, layer 4 header.
A replacement of ip_packet.py.
"""
import struct
import socket
import ipaddress
from collections import OrderedDict
import logging

from .ip_packet import do_csum, IPHeader

logger = logging.getLogger(__name__)


class L4Header:
    # checksum offset to the L4 header
    CHECKSUM_OFFSET_UDP = 6
    CHECKSUM_OFFSET_TCP = 16
    def __init__(self, packet: bytearray = None, offset: int = 20, proto: int = IPHeader.PROTO_ICMP):
        self.packet = packet  # the whole IP packet
        self.offset = offset  # offset to the whole IP packet
        self.checksum_offset : int = 0
        self.checksum : int = 0

        if proto == IPHeader.PROTO_UDP:
            self.checksum_offset = self.CHECKSUM_OFFSET_UDP
        elif proto == IPHeader.PROTO_TCP:
            self.checksum_offset = self.CHECKSUM_OFFSET_TCP

        if self.checksum_offset == 0:
            return

        self.checksum = (int).from_bytes(
            packet[offset+self.checksum_offset: offset+self.checksum_offset+2], 'big')

    def __repr__(self):
        return f'L4 offset: {self.offset}, checksum: {self.checksum}'

    def _update_checksum(self, checksum: int):
        self.packet[self.offset+self.checksum_offset: self.offset+self.checksum_offset+2] = (checksum).to_bytes(2, 'big')

    def dnat(self, old_ip: int, new_ip: int):
        if self.checksum_offset == 0:
            return
        self.checksum = do_csum(self.checksum, old_ip, new_ip)
        self._update_checksum(self.checksum)

    def snat(self, old_ip: int, new_ip: int):
        if self.checksum_offset == 0:
            return
        self.checksum = do_csum(self.checksum, old_ip, new_ip)
        self._update_checksum(self.checksum)


class IPPacket:
    """
    Use a shared bytearray to avoid copy.
    """
    def __init__(self):
        self.packet     : bytearray = None
        self.header     : IPHeader = None
        self.l4_header  : L4Header = None

    def __repr__(self):
        if self.header.version == 4:
            return f'{self.header}\n{self.l4_header}\n'
        else:
            return 'IPv6 packet...'

    def from_network(self, data: bytes) -> 'IPPacket':
        self.packet = bytearray(data)
        self.header = IPHeader().from_network(data[0: IPHeader.LENGTH])
        self.l4_header = L4Header(self.packet, self.header.ihl * 4, self.header.protocol)
        return self

    def to_network(self) -> bytes:
        self.packet[0: IPHeader.LENGTH] = self.header.to_network()
        return bytes(self.packet)

    def dnat(self, new_ip: int):
        """
        If packet is fragmented, can only recaculate the first fragment.
        Because the following packets don't have a layer 4 header!
        """
        if self.header.frag_off == 0:
            self.l4_header.dnat(self.header.dst_ip, new_ip)
        self.header.dnat(new_ip)

    def snat(self, new_ip: int):
        """
        The same as dnat.
        """
        if self.header.frag_off == 0:
            self.l4_header.snat(self.header.src_ip, new_ip)
        self.header.snat(new_ip)

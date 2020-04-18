"""
Handle IP packet, include IP header, layer 4 header.
"""
import struct
import socket
import ipaddress
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


class IPHeader:
    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17

    # only accept the first 20 fixed bytes
    LENGTH = 20

    def __init__(self):
        self.packet : bytes = None
        self.version = 0
        self.ihl = 0
        self.frag_off = 0

        # following are raw/grouped items in 8/16/32 bits
        self.version_ihl = 0
        self.dscp_ecn = 0
        self.length = 0
        self.identification = 0
        self.flag_fragment = 0
        self.ttl = 0
        self.protocol = 0
        self.checksum = 0
        self.src_ip = 0
        self.dst_ip = 0

    def __repr__(self):
        friendly_values = OrderedDict([
            ('version'    , self.version),
            ('ihl'        , self.ihl),
            ('length'     , self.length),
            ('frag_off'   , self.frag_off),
            ('protocol'   , self._get_ipproto(self.protocol)),
            ('source'     , self._get_ipdot(self.src_ip)),
            ('destination', self._get_ipdot(self.dst_ip)),
        ])
        result = '\n'
        for field, value in friendly_values.items():
            result += f'{field.ljust(12)}: {value}\n'
        return result

    @staticmethod
    def _get_ipproto(number: int) -> str:
        table = {num: name[8:] for (name, num) in vars(socket).items() if name.startswith("IPPROTO_")}
        if number in table:
            return table[number]
        else:
            return 'unknown'

    @staticmethod
    def _get_ipdot(ip: int) -> str:
        return ipaddress.IPv4Address(ip).exploded

    def to_network(self) -> bytes:
        return struct.pack(
            '>BBHHHBBHLL',
            self.version_ihl, self.dscp_ecn, self.length,
            self.identification, self.flag_fragment,
            self.ttl, self.protocol, self.checksum,
            self.src_ip,
            self.dst_ip,
        )

    def from_network(self, packet: bytes) -> 'IPHeader':
        """
        packet: IP packet bytes data.
        """
        assert len(packet) == self.LENGTH

        self.packet = packet

        (
            self.version_ihl, self.dscp_ecn, self.length,
            self.identification, self.flag_fragment,
            self.ttl, self.protocol, self.checksum,
            self.src_ip,
            self.dst_ip,
        ) = struct.unpack('>BBHHHBBHLL', packet)

        self.version = self.version_ihl >> 4
        self.ihl = self.version_ihl & 0x0f
        self.frag_off = self.flag_fragment & 0x1fff

        return self

    def dnat(self, new_ip: int):
        new_csum = do_csum(self.checksum, self.dst_ip, new_ip)
        self.dst_ip, self.checksum = new_ip, new_csum

    def snat(self, new_ip: int):
        new_csum = do_csum(self.checksum, self.src_ip, new_ip)
        self.src_ip, self.checksum = new_ip, new_csum


class EmptyL4Header:
    LENGTH = 0
    def __init__(self):
        self.checksum = 0

    def __repr__(self):
        return '<EmptyL4Header with 0 bytes>'

    def from_network(self, data: bytes) -> 'EmptyL4Header':
        return self

    def to_network(self) -> bytes:
        return b''

    def dnat(self, old_ip: int, new_ip: int):
        self.checksum = do_csum(self.checksum, old_ip, new_ip)

    def snat(self, old_ip: int, new_ip: int):
        self.checksum = do_csum(self.checksum, old_ip, new_ip)


class UDPHeader(EmptyL4Header):
    LENGTH = 8
    def __init__(self):
        self.src_port : int = None
        self.dst_port : int = None
        self.length   : int = None
        self.checksum : int = None

    def __repr__(self):
        return f'src_port: {self.src_port}, dst_port: {self.dst_port}'

    def from_network(self, data: bytes) -> 'UDPHeader':
        assert len(data) == self.LENGTH
        self.src_port, self.dst_port, self.length, self.checksum = struct.unpack('>HHHH', data)
        return self

    def to_network(self) -> bytes:
        return struct.pack('>HHHH', self.src_port, self.dst_port, self.length, self.checksum)


class TCPHeader(EmptyL4Header):
    """
    Only interprate first 20 bytes
    """
    LENGTH = 20
    def __init__(self):
        self.src_port : int = None
        self.dst_port : int = None
        self._middles : bytes = None
        self.checksum : int = None
        self.urgent   : int = None

    def __repr__(self):
        return f'src_port: {self.src_port}, dst_port: {self.dst_port}'

    def from_network(self, data: bytes) -> 'TCPHeader':
        assert len(data) == self.LENGTH
        self.src_port, self.dst_port, self._middles, self.checksum, self.urgent = struct.unpack('>HH12sHH', data)
        return self

    def to_network(self) -> bytes:
        return struct.pack('>HH12sHH', self.src_port, self.dst_port, self._middles, self.checksum, self.urgent)


class IPPacket:
    def __init__(self):
        self.packet         : bytes = None
        self.header         : IPHeader = None
        self._header_option : bytes = None
        self.l4_header      : EmptyL4Header = None
        self._l4_body       : bytes = None  # data after tcp/udp header

    def __repr__(self):
        if self.header.version == 4:
            return f'{self.header}\n{self.l4_header}\n'
        else:
            return 'IPv6 packet...'

    def from_network(self, data: bytes) -> 'IPPacket':
        self.packet = data
        self.header = IPHeader().from_network(data[0: IPHeader.LENGTH])
        self._header_option = data[IPHeader.LENGTH: self.header.ihl * 4]

        if self.header.protocol == self.header.PROTO_TCP:
            self.l4_header = TCPHeader()
        elif self.header.protocol == self.header.PROTO_UDP:
            self.l4_header = UDPHeader()
        else:
            self.l4_header = EmptyL4Header()

        self.l4_header.from_network(data[self.header.ihl * 4: self.header.ihl * 4 + self.l4_header.LENGTH])

        self._l4_body = data[self.header.ihl * 4 + self.l4_header.LENGTH: ]

        return self

    def to_network(self) -> bytes:
        return b''.join([
            self.header.to_network(),
            self._header_option,
            self.l4_header.to_network(),
            self._l4_body,
        ])

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


def do_csum(old_sum: int, old_ip: int, new_ip: int) -> int:
    """
    old_sum: 16 bits
    old_ip: 32 bits
    new_ip: 32 bits
    """

    # only in one case: UDP checksum not calculated; otherwise, checksum cann't be 0.
    if 0 == old_sum:
        return 0

    if old_ip == new_ip:
        return old_sum

    old_ip = ~old_ip
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF)
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF)

    new_ip = ~new_ip
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF)
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF)

    # move one bit to left. old_sum must be bigger than 0.
    new_sum = 0x00010000 | (old_sum - 0x00000001)
    new_sum = new_sum - old_ip + new_ip
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF)
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF)
    return new_sum & 0x0000FFFF

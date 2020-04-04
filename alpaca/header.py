"""
Parse the vpn header from network.
"""
import logging
import struct
from collections import OrderedDict

HEADER_LENGTH = 16
ICV_LENGTH = 16

logger = logging.getLogger(__name__)


class Header:
    FIELD_LENGTH = OrderedDict([
        ('type'      ,  4 ),
        ('length'    ,  11),
        ('m'         ,  1 ),
        ('ttl'       ,  4 ),
        ('pi_a'      ,  2 ),
        ('pi_b'      ,  2 ),
        ('src_in'    ,  1 ),
        ('dst_in'    ,  1 ),
        ('reserved'  ,  6 ),
        ('src_id'    ,  16),
        ('dst_id'    ,  16),
        ('timestamp' ,  20),
        ('magic'     ,  12),
        ('sequence'  ,  20),
        ('padding'   ,  12),
    ])

    def __init__(self):
        self.type       = 0
        self.length     = 0
        self.m          = 0
        self.ttl        = 0
        self.pi_a       = 0
        self.pi_b       = 0
        self.src_in     = 0
        self.dst_in     = 0
        self.reserved   = 0
        self.src_id     = 0
        self.dst_id     = 0
        self.timestamp  = 0
        self.magic      = 0
        self.sequence   = 0
        self.padding    = 0

    def __repr__(self):
        result = '\n'
        for field in self.FIELD_LENGTH.keys():
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value}\n'
        return result

    def to_network(self) -> bytes:
        """
        convert to bytes in network byte order.
        """
        type_len_m = (self.type << 12) + (self.length << 1) + self.m
        ttl_pi_sd = (self.ttl << 12) + (self.pi_a << 10) + (self.pi_b << 8) + (self.src_in << 7) + (self.dst_in << 6) + self.reserved
        time_magic = (self.timestamp << 12) + self.magic
        seq_rand = (self.sequence << 12) + self.padding
        return struct.pack(
            '>HHHHLL',
            type_len_m, ttl_pi_sd, self.src_id, self.dst_id, time_magic, seq_rand)

    def get_iv(self) -> bytes:
        """
        Set ttl_pi_sd to 0, and convert to bytes in network byte order.
        """
        type_len_m = (self.type << 12) + (self.length << 1) + self.m
        ttl_pi_sd = 0
        time_magic = (self.timestamp << 12) + self.magic
        seq_rand = (self.sequence << 12) + self.padding
        return struct.pack(
            '>HHHHLL',
            type_len_m, ttl_pi_sd, self.src_id, self.dst_id, time_magic, seq_rand)

    def from_network(self, data: bytes):
        """
        convert from bytes in network byte order.
        """
        assert len(data) == HEADER_LENGTH

        (
            type_len_m, ttl_pi_sd, self.src_id, self.dst_id, time_magic, seq_rand
        ) = struct.unpack('>HHHHLL', data)

        self.type       =   type_len_m >> 12  # (type_len_m & 0xf000) >> 12
        self.length     =  (type_len_m & 0x0ffe) >> 1
        self.m          =   type_len_m & 0x0001

        self.ttl        =   ttl_pi_sd >> 12  # (ttl_pi_sd & 0xf000) >> 12
        self.pi_a       =  (ttl_pi_sd & 0x0c00) >> 10
        self.pi_b       =  (ttl_pi_sd & 0x0300) >> 8
        self.src_in     =  (ttl_pi_sd & 0x0080) >> 7
        self.dst_in     =  (ttl_pi_sd & 0x0040) >> 6
        self.reserved   =   ttl_pi_sd & 0x003f

        self.timestamp  =   time_magic >> 12  # (time_magic & 0xfffff000) >> 12
        self.magic      =   time_magic & 0x00000fff

        self.sequence   =   seq_rand >> 12  # (seq_rand & 0xfffff000) >> 12
        self.padding    =   seq_rand & 0x00000fff

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
        ('type'      ,  3 ),
        ('src_inside',  1 ),
        ('dst_inside',  1 ),
        ('length'    ,  11),
        ('random'    ,  16),
        ('src_id'    ,  16),
        ('dst_id'    ,  16),
        ('timestamp' ,  32),
        ('sequence'  ,  20),
        ('ttl'       ,  4 ),
        ('magic'     ,  8 ),
    ])

    def __init__(self):
        self.type       = 0
        self.src_inside = 0
        self.dst_inside = 0
        self.length     = 0
        self.random     = b''
        self.src_id     = 0
        self.dst_id     = 0
        self.timestamp  = 0
        self.sequence   = 0
        self.ttl        = 0
        self.magic      = 0

    def __repr__(self):
        result = '\n'
        for field in self.FIELD_LENGTH.keys():
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value}\n'
        return result

    def _to_network(self, ttl) -> bytes:
        type_sd_len = (self.type << 13) + (self.src_inside << 12) + (self.dst_inside << 11) + self.length
        seq_ttl_magic = (self.sequence << 12) + (ttl << 8) + self.magic
        return struct.pack(
            '>H2sHHLL',
            type_sd_len, self.random, self.src_id, self.dst_id, self.timestamp, seq_ttl_magic)

    def to_network(self) -> bytes:
        """
        convert to bytes in network byte order.
        """
        return self._to_network(self.ttl)

    def get_iv(self) -> bytes:
        """
        Set ttl to 0, and convert to bytes in network byte order.
        """
        return self._to_network(0)

    def from_network(self, data: bytes):
        """
        convert from bytes in network byte order.
        """
        assert len(data) == HEADER_LENGTH

        (
            type_sd_len, self.random, self.src_id, self.dst_id, self.timestamp, seq_ttl_magic
        ) = struct.unpack('>H2sHHLL', data)

        self.type       =   type_sd_len >> 13
        self.src_inside =  (type_sd_len & 0x1000) >> 12
        self.dst_inside =  (type_sd_len & 0x0800) >> 11
        self.length     =   type_sd_len & 0x07ff

        self.sequence   =   seq_ttl_magic >> 12
        self.ttl        =  (seq_ttl_magic & 0x00000f00) >> 8
        self.magic      =   seq_ttl_magic & 0x000000ff

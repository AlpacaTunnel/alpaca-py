"""
Parse the vpn header from network.
"""
import struct
from collections import OrderedDict

HEADER_LENGTH = 16


class Header:
    FIELD_LENGTH = OrderedDict([
        ('length'    ,  16),
        ('magic'     ,  16),
        ('src_id'    ,  16),
        ('dst_id'    ,  16),
        ('timestamp' ,  32),
        ('sequence'  ,  32),
    ])

    def __init__(self):
        (
            self.length, self.magic, self.src_id, self.dst_id, self.timestamp, self.sequence
        ) = (0, 0, 0, 0, 0, 0)

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
        return struct.pack(
            '>HHHHLL',
            self.length, self.magic, self.src_id, self.dst_id, self.timestamp, self.sequence
        )

    def from_network(self, data: bytes):
        """
        convert from bytes in network byte order.
        """
        assert len(data) == HEADER_LENGTH

        (
            self.length, self.magic, self.src_id, self.dst_id, self.timestamp, self.sequence
        ) = struct.unpack('>HHHHLL', data)

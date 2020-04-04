"""
Load ID and PSK from secret.txt.
"""
from typing import Tuple, List, Iterable
import logging
import ctypes
from multiprocessing.sharedctypes import Array

from .common import truncate_key, ip_ntop, ip_pton

MAX_ID = 65535
MAX_ADDR = 4  # each peer stores 4 addresses

logger = logging.getLogger(__name__)


class PeerAddr(ctypes.Structure):
    _fields_ = [
        ('version', ctypes.c_int8),
        ('ip', ctypes.c_uint32),
        ('port', ctypes.c_uint16),
        ('last_active', ctypes.c_uint32),
    ]

    def __eq__(self, other) -> bool:
        return (self.version == other.version) and (self.ip == other.ip) and (self.port == other.port)

    def __ne__(self, other) -> bool:
        return (not self.__eq__(other))

    def __hash__(self):
        return (self.ip << 16) + self.port

    def __repr__(self):
        return f"{ip_ntop(self.ip)}:{self.port}"


class Peer:
    def __init__(self,
                 id: int = None,
                 psk: bytes = None,
                 addr_array: List[PeerAddr] = None,
    ):
        self.id = id
        self.psk = psk
        self.addr_array = addr_array
        self.offset = self.id * MAX_ADDR

    def add_addr(self, addr: PeerAddr):
        # skip if already stored
        for index in range(self.offset, self.offset + MAX_ADDR):
            if self.addr_array[index] == addr:
                return

        # store in first empty pointer
        for index in range(self.offset, self.offset + MAX_ADDR):
            if self.addr_array[index].port == 0:
                self.addr_array[index] = addr
                return

    def get_addrs(self) -> Iterable[PeerAddr]:
        my_array = self.addr_array[self.offset: self.offset + MAX_ADDR]
        return filter(lambda addr: addr.port, my_array)

    def __repr__(self):
        return f'{self.id} {self.psk.hex()} {list(self.get_addrs())}'


class PeerPool:
    def __init__(self, secret_path: str = None):
        self.secret_path = secret_path
        self.pool = dict()
        # use shared Array to sync address between multiprocessing.Process
        # it's much faster than multiprocessing.Manager().dict()
        self.addr_array = Array(PeerAddr, MAX_ID * MAX_ADDR)

    def __repr__(self):
        result = '\n'
        for peer in self.pool.values():
            result += f'{peer}\n'
        return result

    def _strip_line(self, line: str) -> Tuple[str]:
        if not line.strip() or line.strip().startswith('#'):
            return (None, ) * 5

        items = line.split()[:5]

        if len(items) < 5:
            items.extend([None] * (5 - len(items)))
        
        for index, value in enumerate(items):
            if value in ('null', 'None'):
                items[index] = None

        return items

    def _load_line(self, line: str):
        id_str, psk, ip, _ip6, port = self._strip_line(line)
        if not id_str or not psk:
            return

        id = int(id_str.split('.')[0]) * 256 + int(id_str.split('.')[1])

        self.pool[id] = Peer(id, truncate_key(psk), self.addr_array)

        if ip and port:
            addr = PeerAddr(4, ip_pton(ip), int(port))
            self.pool[id].add_addr(addr)

    def load(self) -> 'PeerPool':
        with open(self.secret_path) as f:
            for line in f.readlines():
                self._load_line(line)

        return self

"""
Load ID and PSK from secret.txt.
"""
from typing import Tuple, List, Dict
import logging
import ctypes
import time
from multiprocessing.sharedctypes import Array

from .common import truncate_key, ip_ntop, ip_pton, id_pton

MAX_ID = 65535
# Each peer stores 4 addresses, increase if need more forwarders. It seems path_index in header is not nessary?
MAX_ADDR = 4

logger = logging.getLogger(__name__)


class PeerAddr(ctypes.Structure):
    _fields_ = [
        ('static', ctypes.c_bool),
        ('version', ctypes.c_int8),
        ('ip', ctypes.c_uint32),
        ('port', ctypes.c_uint16),
        ('last_active', ctypes.c_uint64),
    ]

    def __eq__(self, other) -> bool:
        return (self.version == other.version) and (self.ip == other.ip) and (self.port == other.port)

    def __ne__(self, other) -> bool:
        return (not self.__eq__(other))

    def __hash__(self):
        return (self.ip << 16) + self.port

    def __repr__(self):
        return f"{ip_ntop(self.ip)}:{self.port}"


class PktFilter:
    """
    For each packet with a specified timestamp and sequence, mark True.
    If the same timestamp and sequence is received again, drop it.

    Simple version, client clock cann't change backword.
    """
    RATE_LIMIT = 160000  # pps
    def __init__(self, limit: int = RATE_LIMIT):
        self.limit = limit
        self.latest: int = 0
        self.mark_0 = [False, ] * self.limit
        self.mark_1 = [False, ] * self.limit
        self.mark_2 = [False, ] * self.limit

    def is_valid(self, timestamp: int, sequence: int) -> bool:
        # TODO: filter too many timestamp jump, maybe attack
        if sequence >= self.limit:
            return False

        if self._is_dup(timestamp, sequence):
            logger.debug('Pkt is duplicated')
            return False

        return True

    def _is_dup(self, timestamp: int, sequence: int) -> bool:
        time_diff = timestamp - self.latest

        # let's assume max delay is 600s
        # if time_diff < -600, it should be timestamp jump from max to 0
        if time_diff > 2 or time_diff < -600:
            self.latest = timestamp
            self.mark_2 = [False, ] * self.limit
            self.mark_1 = [False, ] * self.limit
            self.mark_0 = [False, ] * self.limit

            self.mark_0[sequence] = True
            return False

        elif time_diff == 2:
            self.latest = timestamp
            self.mark_2 = self.mark_0
            self.mark_1 = [False, ] * self.limit
            self.mark_0 = [False, ] * self.limit

            self.mark_0[sequence] = True
            return False

        elif time_diff == 1:
            self.latest = timestamp
            self.mark_2 = self.mark_1
            self.mark_1 = self.mark_0
            self.mark_0 = [False, ] * self.limit

            self.mark_0[sequence] = True
            return False

        elif time_diff == 0:
            if self.mark_0[sequence]:
                return True
            else:
                self.mark_0[sequence] = True
                return False

        elif time_diff == -1:
            if self.mark_1[sequence]:
                return True
            else:
                self.mark_1[sequence] = True
                return False

        elif time_diff == -2:
            if self.mark_2[sequence]:
                return True
            else:
                self.mark_2[sequence] = True
                return False

        # -2 > time_diff > -600, do nothing and treat it as not dup
        return False


class Peer:
    def __init__(self,
                 id: int = None,
                 psk: bytes = None,
                 addr_array: List[PeerAddr] = None,
    ):
        self.id = id
        self.psk = psk
        self.addr_array: List[PeerAddr] = addr_array
        self._offset = self.id * MAX_ADDR  # offset to the shared addr_array
        self.pkt_filter: PktFilter = None

    def init_pkt_filter(self):
        """
        Only init it in receive subprocess.
        """
        if self.pkt_filter is None:
            self.pkt_filter = PktFilter()

    def add_addr(self, addr: PeerAddr):
        if addr.port == 0:
            logger.error('Got wrong address with port 0.')
            return

        # update last_active timestamp if already stored
        for index in range(self._offset, self._offset + MAX_ADDR):
            if self.addr_array[index] == addr:
                self.addr_array[index].last_active = int(time.time())
                return

        # store in first empty pointer
        for index in range(self._offset, self._offset + MAX_ADDR):
            if self.addr_array[index].port == 0:
                self.addr_array[index] = addr
                self.addr_array[index].last_active = int(time.time())
                return

    def get_addrs(self, static=False) -> List[PeerAddr]:
        """
        If static, only return static addrs.
        Else return all static and active dynamic (last_active within 60s)
        """
        my_array = self.addr_array[self._offset: self._offset + MAX_ADDR]
        if static:
            return list(filter(lambda addr: addr.port and addr.static, my_array))

        # clear inactive dynamic addresses
        for addr in filter(
                lambda addr: addr.port and not addr.static and (int(time.time()) - addr.last_active) > 60,
                my_array):
            addr.port = 0

        return list(filter(lambda addr: addr.port, my_array))

    def __repr__(self):
        return f'{self.id} {self.psk.hex()} {list(self.get_addrs())}'


class PeerPool:
    def __init__(self, secret_path: str = None):
        self.secret_path = secret_path
        self.pool: Dict[int, Peer] = dict()
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

        id = id_pton(id_str)

        self.pool[id] = Peer(id, truncate_key(psk), self.addr_array)

        if ip and port:
            addr = PeerAddr(
                static=True,
                version=4,
                ip=ip_pton(ip),
                port=int(port),
                last_active=0,
            )
            self.pool[id].add_addr(addr)

    def load(self) -> 'PeerPool':
        with open(self.secret_path) as f:
            for line in f.readlines():
                self._load_line(line)

        return self

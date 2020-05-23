"""
Load ID and PSK from secret.txt.
Bigger ID is client, smaller ID is server.
"""
from typing import Tuple, List, Dict
import logging
import ctypes
import time
from multiprocessing import Value
from multiprocessing.sharedctypes import Array

from .common import truncate_key, id_pton

MAX_ID = 65535
# Each peer stores 4 addresses, increase if need more forwarders.
MAX_ADDR = 4

logger = logging.getLogger(__name__)


class PeerAddr(ctypes.Structure):
    _fields_ = [
        ('static', ctypes.c_bool),
        ('version', ctypes.c_int8),
        ('ip', ctypes.c_wchar * 20),
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
        mark = 'Static' if self.static else 'Dynamic'
        return f"{self.ip}:{self.port} ({mark}-{self.last_active})"

    def copy(self, other: 'PeerAddr'):
        self.static = other.static
        self.version = other.version
        self.ip = other.ip
        self.port = other.port
        self.last_active = other.last_active

    def clear_inactive_dynamic(self):
        if self.port and not self.static and (int(time.time()) - self.last_active) > 60:
            self.port = 0


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
        if sequence >= self.limit:
            logger.debug('Pkt sequence number exceeded limit')
            return False

        if abs(timestamp - int(time.time())) > 2592000:
            logger.debug('Peer timestamp shifts beyond 30 days')
            return False

        if timestamp - self.latest < -600:
            logger.debug('Pkt delayed more than 600s, treat as invalid')
            return False

        if self._is_dup(timestamp, sequence):
            logger.debug('Pkt is duplicated')
            return False

        return True

    def _is_dup(self, timestamp: int, sequence: int) -> bool:
        time_diff = timestamp - self.latest

        if time_diff > 2:
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

        # if time_diff < -2, do nothing and treat it as not dup
        return False


class Peer:
    def __init__(self,
                 id: int = None,
                 psk: bytes = None,
                 shared_array: List[PeerAddr] = None,
    ):
        self.id = id
        self.psk = psk
        self.pkt_filter: PktFilter = None

        # How to sync address from worker_recv to worker_send?
        # Use multiprocessing.sharedctypes.Array is faster than multiprocessing.Manager, but still slow.
        # It turns out multiprocessing.Value is fast, so use it as a signal.
        self.shared_array: List[PeerAddr] = shared_array
        self._offset = self.id * MAX_ADDR  # offset to the shared shared_array
        self.addr_updated = Value('i', 1)  # use an integer to indicate bool, shared by multiprocessing

        # worker_recv._addr_list -> shared_array -> worker_send._addr_list

        # In each subprocess, store the addresses in a local list.
        self._addr_list: List[PeerAddr] = [PeerAddr(port=0) for _ in range(MAX_ADDR)]  # not shared
        self._last_synced = 0  # timestamp, not shared, used by worker_recv
        self._last_cleared = 0  # timestamp, not shared, used by worker_send

    def init_pkt_filter(self):
        """
        Only init it in receive subprocess.
        """
        if self.pkt_filter is None:
            self.pkt_filter = PktFilter()

    def _clear_inactive_addr(self):
        """
        Only clear the addr in the calling worker process.
        """
        for addr in self._addr_list:
            addr.clear_inactive_dynamic()

    def _update_timestamp_if_stored(self, new_addr: PeerAddr) -> bool:
        """
        update last_active timestamp if already stored
        """
        for addr in self._addr_list:
            if addr == new_addr:
                addr.last_active = int(time.time())
                return True
        return False

    def _add_to_local_list(self, new_addr: PeerAddr) -> bool:
        """
        store in first empty addr
        """
        for addr in self._addr_list:
            if addr.port == 0:
                addr.copy(new_addr)
                addr.last_active = int(time.time())
                return True
        return False

    def add_addr(self, new_addr: PeerAddr):
        """
        This method is called in worker_recv (and by main on vpn start).
        """
        added, stored = False, False

        stored = self._update_timestamp_if_stored(new_addr)

        if not stored:
            self._clear_inactive_addr()
            added = self._add_to_local_list(new_addr)

        if added:
            self._sync_to_shared_array()
            logger.debug('added new_addr in worker_recv')

        # even if not added, still sync periodically, because addr timestamp is updated
        if not added and (int(time.time()) - self._last_synced) > 10:
            self._clear_inactive_addr()
            self._sync_to_shared_array()
            logger.debug('sync to shared_array in worker_recv by period')

    def _sync_to_shared_array(self):
        self.shared_array[self._offset: self._offset + MAX_ADDR] = self._addr_list[:]
        self.addr_updated.value = 1
        self._last_synced = int(time.time())
        logger.debug(self._addr_list)

    def _sync_from_shared_array(self):
        if not self.addr_updated.value:
            return
        self._addr_list[:] = self.shared_array[self._offset: self._offset + MAX_ADDR]
        self.addr_updated.value = 0
        logger.debug('updated in worker_send')
        logger.debug(self._addr_list)
        self._update_cache()

    def _update_cache(self):
        # all static and active dynamic, after _clear_inactive_addr()
        # Note: use tuple to prevent change by caller function.
        valid_addrs = tuple(filter(lambda addr: addr.port, self._addr_list))

        self.addrs_all_static_dynamic = valid_addrs
        self.addrs_all_static = tuple(filter(lambda addr: addr.static, valid_addrs))
        self.addrs_all_dynamic = tuple(filter(lambda addr: not addr.static, valid_addrs))
        self.addrs_all_active = tuple(filter(lambda addr: (int(time.time()) - addr.last_active) < 60, valid_addrs))

    def _clear_periodically(self):
        if (int(time.time()) - self._last_cleared) < 10:
            return
        # clear inactive dynamic addresses
        # Don't do this in add_addr, because add_addr is not called if no pkt in.
        self._clear_inactive_addr()
        self._update_cache()
        self._last_cleared = int(time.time())
        logger.debug('cleared in worker_send by period')

    def get_addrs(self, static=False, inactive_downward_static=False) -> Tuple[PeerAddr]:
        """
        This method is called in worker_send.
        -> If static, only return static addrs (both active/inactive).
        -> If inactive_downward_static, send to active dynamic + all static.
        -> If there are active static+dynamic, return them.
        -> Return inactive static. (dynamic is always active.)
        """
        self._sync_from_shared_array()
        self._clear_periodically()

        if static:
            return self.addrs_all_static

        # Consider the topology with a server, a client, a forwarder:
        #
        #  server ---- forwarder ------|
        #      |-----------------------|---- client
        #
        # The client sends pkt to server both directly and via a forwarder (server is configured as a forwarder).
        # If client to server direct upward link is blocked by firewall, then downward pkt
        # can only go throuth forwarder, even if server to client downward link still works,
        # and even if they all have each other's static addresses (because it's inactive).
        # To use server-to-client downward link, send to client's inactive static addr (if inactive_downward_static is True).
        # In this case, upward/downward path is not the same in the view of the server.

        # active dynamic + all static
        if inactive_downward_static:
            return self.addrs_all_static_dynamic

        # if static addr is not active, don't send to it, in case upward/downward path not the same.
        if self.addrs_all_active:
            return self.addrs_all_active

        # send to inactive static addr, in case no dynamic addr found.
        return self.addrs_all_static_dynamic

    def __repr__(self):
        return f'{self.id} {self.psk.hex()} {list(self.get_addrs())}'


class PeerPool:
    def __init__(self, secret_path: str = None):
        self.secret_path = secret_path
        self.pool: Dict[int, Peer] = dict()
        # use shared Array to sync address between multiprocessing.Process
        # it's much faster than multiprocessing.Manager().dict()
        self.shared_array = Array(PeerAddr, MAX_ID * MAX_ADDR)

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

        self.pool[id] = Peer(id, truncate_key(psk), self.shared_array)

        if ip and port:
            addr = PeerAddr(
                static=True,
                version=4,
                ip=ip,
                port=int(port),
            )
            self.pool[id].add_addr(addr)

    def load(self) -> 'PeerPool':
        with open(self.secret_path) as f:
            for line in f.readlines():
                self._load_line(line)

        return self

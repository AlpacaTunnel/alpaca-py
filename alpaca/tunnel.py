"""
Add and delete tuntap interface on Linux.
"""
import re
import ipaddress
import struct
import fcntl

from .common import exec_cmd

DEFAULT_MTU = 1408
NET_MASK = 16

IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca


class Tunnel:

    def __init__(self, name: str, mtu: int = DEFAULT_MTU, IPv4: str = None, IPv6: str = None):
        self.name = name
        self.mtu = mtu
        self.IPv4 = IPv4
        self.IPv6 = IPv6

    def _cmd(self, c, strict=True) -> str:
        rc, output = exec_cmd(c)

        if strict and int(rc) != 0:
            raise Exception(f'cmd ({c}) error: {output}')

        return output

    def _exists(self) -> bool:
        for line in self._cmd('ip link').splitlines():
            re_obj = re.match(r'^[0-9]+:\s+(.*?):\s+<', line)
            if not re_obj:
                continue

            interface = re_obj.group(1)
            if interface == self.name:
                return True

        return False

    def _ip_overlaps(self, ip: str) -> bool:
        if ':' in ip:
            ip_cls = ipaddress.IPv6Network
            matching = 'inet6'
        else:
            matching = 'inet4'
            ip_cls = ipaddress.IPv4Network

        inet_self = ip_cls(ip, False)

        for line in self._cmd('ip addr').splitlines():
            line = line.lstrip()
            re_obj = re.match(rf'^{matching}\s+(.*?)\s', line)
            if not re_obj:
                continue

            inet = ip_cls(re_obj.group(1), False)
            if inet.overlaps(inet_self):
                return True

        return False

    def _add_ip(self, ip: str):
        if not ip:
            return
        if self._ip_overlaps(ip):
            raise Exception(f'tunnel {self.name}: IP overlaps with other interface')
        self._cmd(f'ip addr add {ip}/{NET_MASK} dev {self.name}')

    def _add_dev(self):
        if self._exists():
            raise Exception(f'tunnel {self.name} already exists, nothing to do!')
        self._cmd(f'ip tuntap add dev {self.name} mode tun')
        self._cmd(f'ip link set {self.name} up')
        self._cmd(f'ip link set {self.name} mtu {self.mtu}')

    def add(self) -> 'Tunnel':
        self._add_dev()
        self._add_ip(self.IPv4)
        self._add_ip(self.IPv6)
        return self

    def delete(self) -> 'Tunnel':
        if self._exists():
            self._cmd(f'ip tuntap del dev {self.name} mode tun')
        return self

    def open(self) -> int:
        if not self._exists():
            raise Exception(f'device not exists {self.name}')

        ifr = struct.pack('16sH', str.encode(self.name), IFF_TUN | IFF_NO_PI)
        tun_fd = open('/dev/net/tun', mode='r+b', buffering=0)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

        return tun_fd

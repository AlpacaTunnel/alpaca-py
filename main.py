#!/usr/bin/env python3

"""
  A simple user-space peer-to-peer UDP-based tunnel.

  sudo ip tuntap add dev tun9 mode tun
  sudo ip link set tun9 up
  sudo ip addr add 10.0.1.2/24 dev tun9
  sudo ip link set tun9 mtu 1408

  ./udptun.py tun9 8964 172.16.89.64 1984

"""

import logging
import time
import socket
import argparse
import traceback
from multiprocessing import Process
from multiprocessing import Process as Worker
# from threading import Thread as Worker

from alpaca.config import Config
from alpaca.peer import PeerPool, PeerAddr
from alpaca.common import ip_pton, ip_ntop
from alpaca.tunnel import Tunnel
from alpaca.vpn_in import VPNIn
from alpaca.vpn_out import VPNOut

ETH_MTU = 1500
LOGFORMAT = '[%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s()] - %(message)s'


def worker_send(sock, tun, conf, peers):
    ctx_out = VPNOut(conf, peers)
    while True:
        try:
            body = tun.read(ETH_MTU)
            addrs, packet = ctx_out.get_outter_packet(body)
            if packet:
                for addr in addrs:
                    sock.sendto(packet, (ip_ntop(addr.ip), addr.port))
        except Exception as e:
            traceback.print_exc()
            print('Got Exception in worker_send: %s' % e)


def worker_recv(sock, tun, conf, peers):
    ctx_in = VPNIn(conf, peers)
    while True:
        try:
            packet, ip_port = sock.recvfrom(ETH_MTU)
            addr = PeerAddr(4, ip_pton(ip_port[0]), int(ip_port[1]))
            body = ctx_in.get_inner_packet(packet, addr)
            if body:
                tun.write(body)
        except Exception as e:
            traceback.print_exc()
            print('Got Exception in worker_recv: %s' % e)


def start_server(tun, conf, peers):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', conf.port))

    # Worker(target=worker_send, args = (sock, tun, conf, peers)).start()
    Worker(target=worker_recv, args = (sock, tun, conf, peers)).start()

    worker_send(sock, tun, conf, peers)
    # worker_recv(sock, tun, conf, peers)

    while True:
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--conf', default=None, help='path to the configure file')
    args = parser.parse_args()

    conf = Config(args.conf)
    logging.basicConfig(format=LOGFORMAT, level=conf.log_level)
    peers = PeerPool(conf.secret_file).load()

    print(conf)
    print(peers)

    tun = Tunnel(conf.name, conf.mtu, f'{conf.net}.{conf.id}')
    tun_fd = tun.delete().add().open()

    start_server(tun_fd, conf, peers)


if __name__ == "__main__":
    main()

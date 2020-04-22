#!/usr/bin/env python3

import logging
import time
import sys
import socket
import argparse
import traceback
from multiprocessing import Process as Worker
# from threading import Thread as Worker

from alpaca.config import Config
from alpaca.peer import PeerPool, PeerAddr
from alpaca.common import ip_pton, ip_ntop
from alpaca.tunnel import Tunnel
from alpaca.system import System, install_signal_restore
from alpaca.vpn import VPN
from alpaca.pkt_in import PktIn
from alpaca.pkt_out import PktOut

ETH_MTU = 1500
LOGFORMAT = '[%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s()] - %(message)s'
logger = logging.getLogger(__name__)


def worker_send(sock, tun, vpn):
    while vpn.running.value:
        try:
            body = tun.read(ETH_MTU)
            pkt = PktOut(vpn, body)
            if not pkt.valid:
                continue
            for addr in pkt.dst_addrs:
                sock.sendto(pkt.outter_pkt, (ip_ntop(addr.ip), addr.port))
        except Exception as exc:
            logger.debug(traceback.format_exc())
            logger.error(f'Got Exception in worker_send: {exc.__class__.__name__}: {exc}')

    logger.info('worker_send has ended.')


def worker_recv(sock, tun, vpn):
    while vpn.running.value:
        try:
            packet, ip_port = sock.recvfrom(ETH_MTU)
            addr = PeerAddr(
                static=False,
                version=4,
                ip=ip_pton(ip_port[0]),
                port=int(ip_port[1]),
            )
            pkt = PktIn(vpn, packet, addr)
            if not pkt.valid:
                continue

            if pkt.action == pkt.ACTION_WRITE:
                tun.write(pkt.body)

            if pkt.action == pkt.ACTION_FORWARD:
                for addr in pkt.dst_addrs:
                    sock.sendto(pkt.new_outter_pkt, (ip_ntop(addr.ip), addr.port))

        except Exception as exc:
            logger.debug(traceback.format_exc())
            logger.error(f'Got Exception in worker_recv: {exc.__class__.__name__}: {exc}')

    logger.info('worker_recv has ended.')


def start_server(sock, tun, system, vpn):
    Worker(target=worker_send, args=(sock, tun, vpn)).start()
    Worker(target=worker_recv, args=(sock, tun, vpn)).start()

    # worker_send(sock, tun, vpn)
    # worker_recv(sock, tun, vpn)

    # the `kill` cmd won't send signal to child process
    install_signal_restore(system, vpn)

    while vpn.running.value:
        time.sleep(1)

    logger.info('The main progress has ended.')


def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--conf', default=None, help='path to the configure file')
    args = parser.parse_args()

    conf = Config(args.conf)
    logging.basicConfig(format=LOGFORMAT, level=conf.log_level)

    peers = PeerPool(conf.secret_file).load()

    logger.debug(conf)
    logger.debug(peers)

    tun = Tunnel(conf.name, conf.mtu, f'{conf.net}.{conf.id}')
    tun_fd = tun.delete().add().open()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', conf.port))

    vpn = VPN(conf, peers)
    system = System(conf, peers)

    if conf.mode == 'client':
        try:
            system.init()
        except Exception:
            system.restore()
            sys.exit(1)

    start_server(sock, tun_fd, system, vpn)


if __name__ == "__main__":
    main()

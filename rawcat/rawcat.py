#!/usr/bin/env python3

import logging
import os
import psutil
import select
import socket
import sys

from argparse import ArgumentParser
from scapy.all import *

log = logging.getLogger(__name__)

ETH_P_IP = 0x800
PF_IP = socket.ntohs(ETH_P_IP)
OT_IP = sys.argv[1]

class RawCat():
    def __init__(self, dstip, rawsrc=31337, rawdst=31337, uds='/tmp/rawsock'):
        self.rawsrc = rawsrc
        self.rawdst = rawdst
        self.uds = uds
        self.dstip = dstip
        self.rawsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)

        if os.path.exists(uds):
            os.unlink(uds)

        self.uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds.bind(uds)
        self.uds.listen(1)

    def loop(self):
        while True:
            conn, addr = self.uds.accept()
            while conn:
                r,_,_ = select.select([conn, self.rawsock], [], [])
                for sock in r:
                    if sock == conn:
                        msg = conn.recv(8192)
                        if not msg:
                            conn = None
                            break
                        self.send_msg(msg)

                    elif sock == self.rawsock:
                        self.recv_msg(conn)

    def __del__(self):
        self.rawsock.close()

    def for_me(self, p):
        return (p.haslayer(UDP) and
                p[UDP].dport == self.rawdst and
                p[UDP].sport == self.rawsrc)

    def iface_for_pkt(self, p):
        return [k for k,v in psutil.net_if_addrs().items() if p.payload.src in 
                   [a.address for a in v]
               ][0]

    def send_msg(self, msg):
        while len(msg) > 0:
            payload = msg[:1024]
            msg = msg[1024:]

            p = Ether()/IP(dst=self.dstip)/UDP(dport=self.rawdst,sport=self.rawsrc)/payload
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)
            sock.bind((self.iface_for_pkt(p), socket.AF_PACKET))
            payload = bytes(p)
            sock.send(bytes(p))
        sock.close()

    def recv_msg(self, conn):
        p = Ether(self.rawsock.recv(65535))
        if self.for_me(p):
            log.debug(f'Got packet len: {len(bytes(p[UDP].payload))}')
            try:
                conn.send(bytes(p[UDP].payload))
            except BrokenPipeError as e:
                pass

def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


desc = '''Binds a UDS, and transports messages to/from over a packet socket'''
epi = '''THIS IS A TOY PROJECT, NOT MEANT FOR PRODUCTION TRAFFIC'''
    
def parse_args(args):
    parser = ArgumentParser(prog='RawCat',
                            description=desc,
                            epilog=epi)

    parser.add_argument('-s', '--sock', type=str, default='/tmp/rawsock',
                        help='UDS path')
    parser.add_argument('--src-port', type=int, default=31337,
                        help='Source port for raw socket traffic')
    parser.add_argument('--dst-port', type=int, default=31337,
                        help='Dest port for raw socket traffic')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debugging output')
    parser.add_argument('dstip', type=str, help='Destination IP for raw traffic')
    return parser.parse_args(args)

def main():
    options = parse_args(sys.argv[1:])
    init_logging(options.debug)
    rc = RawCat(options.dstip,
                 rawsrc=options.src_port,
                 rawdst=options.dst_port,
                 uds=options.sock)
    try:
        rc.loop()
    except KeyboardInterrupt:
        del(rc)

if __name__ == '__main__':
    main()

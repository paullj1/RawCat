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
BUF_SIZE = 1024
PSH = 0x08
ACK = 0x10

class RawCat():
    def __init__(self, dstip, tcp=False, rawsrc=31337, rawdst=31337,
            uds='/tmp/rawsock'):
        self.rawsrc = rawsrc
        self.rawdst = rawdst
        self.uds = uds
        self.dstip = dstip
        self.tcp = tcp
        self.rawsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)

        if os.path.exists(uds):
            os.unlink(uds)

        self.uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds.bind(uds)
        self.uds.listen(1)

    def handle_client(self):
        conn, addr = self.uds.accept()
        while conn:
            r,_,_ = select.select([conn, self.rawsock], [], [])
            for sock in r:
                if sock == conn:
                    msg = conn.recv(BUF_SIZE)
                    if not msg:
                        conn = None
                        break
                    self.send_msg(msg)

                elif sock == self.rawsock:
                    self.recv_msg(conn)

    def __del__(self):
        self.rawsock.close()

    def for_me(self, p):
        if self.tcp:
            return (p.haslayer(TCP) and
                    p[TCP].dport == self.rawdst and
                    p[TCP].sport == self.rawsrc and
                    p[TCP].flags == 'PA')
        return (p.haslayer(UDP) and
                p[UDP].dport == self.rawdst and
                p[UDP].sport == self.rawsrc)

    def iface_for_pkt(self, p):
        return [k for k,v in psutil.net_if_addrs().items() if p.payload.src in 
                   [a.address for a in v]
               ][0]

    def send_msg(self, msg):
        while len(msg) > 0:
            payload = msg[:BUF_SIZE]
            msg = msg[BUF_SIZE:]

            p = self.gen_raw_pkt(payload)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)
            sock.bind((self.iface_for_pkt(p), socket.AF_PACKET))
            payload = bytes(p)
            sock.send(bytes(p))
        sock.close()

    def gen_raw_pkt(self, payload):
        if self.tcp:
            return Ether()/IP(dst=self.dstip)/TCP(dport=self.rawdst,
                                                  sport=self.rawsrc,
                                                  flags=(PSH|ACK))/payload
        return Ether()/IP(dst=self.dstip)/UDP(dport=self.rawdst,
                                              sport=self.rawsrc)/payload

    def parse_raw_pkt(self, buf):
        return Ether(buf)

    def recv_msg(self, conn):
        p = self.parse_raw_pkt(self.rawsock.recv(65535))
        if not self.for_me(p):
            return

        try:
            if self.tcp:
                log.debug(f'Got packet len: {len(bytes(p[TCP].payload))}')
                conn.send(bytes(p[TCP].payload))
            else:
                log.debug(f'Got packet len: {len(bytes(p[UDP].payload))}')
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
    parser.add_argument('--tcp', action='store_true', 
                        help='Use TCP for raw socket')
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
                 tcp=options.tcp,
                 rawsrc=options.src_port,
                 rawdst=options.dst_port,
                 uds=options.sock)
    try:
        while True:
            rc.handle_client()
    except KeyboardInterrupt:
        del(rc)

if __name__ == '__main__':
    main()

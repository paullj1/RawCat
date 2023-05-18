#!/usr/bin/env python3

import logging
import os
import select
import socket
import sys

from argparse import ArgumentParser
from datetime import datetime, timedelta

from .constants import *
from .reliability import ReliableRawSocket

log = logging.getLogger(__name__)

class RawCat():
    def __init__(self, dstip, tcp=False, rawsrc=31337, rawdst=31337,
            uds='/tmp/rawsock'):
        self.uds_path = uds
        self.rawsock = ReliableRawSocket(dstip, tcp, rawsrc, rawdst)

        if os.path.exists(uds):
            os.unlink(uds)

        self.uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds.bind(uds)
        self.uds.listen(1)

    def handle_client(self):
        conn, addr = self.uds.accept()
        retry_timer = self.get_retry_delay()
        while conn.fileno() > 0:
            r,_,_ = select.select([conn, self.rawsock.recvsock], [], [])
            for sock in r:
                if sock == conn:
                    msg = conn.recv(BUF_SIZE)
                    if not msg:
                        conn.close()
                        self.rawsock.fin()
                        break
                    self.rawsock.send_msg(msg)

                elif sock == self.rawsock.recvsock:
                    self.rawsock.recv_msg(conn)

            self.rawsock.flush_inbuff(conn)
            if datetime.now() > retry_timer:
                log.debug("Queues: Out: %d In: %d", (
                    len(self.rawsock.outbuff.keys()),
                    len(self.rawsock.inbuff.keys())
                ))
                retry_timer = self.get_retry_delay()
                self.rawsock.retry_unackd()
        self.rawsock.reset()

    def get_retry_delay(self):
        return datetime.now() + timedelta(milliseconds=200)

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

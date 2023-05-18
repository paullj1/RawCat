#!/usr/bin/env python3

import random
import socket
import psutil
import struct

from scapy.all import *
from .constants import *

log = logging.getLogger(__name__)

class ReliableRawSocket():
    def __init__(self, dstip, tcp=False, rawsrc=31337, rawdst=31337):
        self.dstip = dstip
        self.tcp = tcp
        self.rawsrc = rawsrc
        self.rawdst = rawdst

        self.recvsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)
        self.sendsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, PF_IP)
        self.sendsock.bind((self.get_source_addr(), socket.AF_PACKET))

        self.inbuff = dict()
        self.outbuff = dict()
        self.inseq = None
        self.outseq = random.randint(0,MAX_SEQ)

    def __del__(self):
        self.recvsock.close()
        self.sendsock.close()

    def recv_msg(self, conn):
        p = self.parse_raw_pkt(self.recvsock.recv(MAX_RECV))
        if not self.for_me(p):
            return

        try:
            if self.tcp:
                seq = p[TCP].seq
                flags = p[TCP].flags.value
                payload = bytes(p[TCP].payload)
            else:
                buf = bytes(p[UDP].payload)
                flags, seq = struct.unpack('=BH', buf[0:3])
                payload = buf[3:]

            log.debug(f'Got packet len: {len(payload)}, flags: {flags}, seq: {seq}')
            if self.inseq:
                log.debug(f'Expecting seq: {self.inseq}')
            else:
                self.inseq = seq

            # Request to initialize session
            if flags == FIN:
                log.debug(f'Fin packet with seq: {seq}')
                conn.close()
                self.send_pkt(seq=seq, flags=ACK)
                self.reset()
                return

            # Ack for sent message; delete from outbuff
            if flags == ACK:
                log.debug(f'Ack packet for seq: {seq}')
                if seq in self.outbuff:
                    self.outbuff.pop(seq)
                return

            # Received message, in order, send to connected client
            if seq == self.inseq and flags & PSH == PSH and len(payload) > 0:
                self.send_pkt(seq=seq, flags=ACK)

                self.inseq = (self.inseq + 1) % MAX_SEQ
                conn.send(payload)

                # Now flush any pending messages
                # TODO Handle wrap around
                sorted_keys = list(self.inbuff.keys()).sort()
#               while sorted_keys[0] 
                while sorted_keys and len(sorted_keys) > 0 and sorted_keys[0] == self.inseq:
                    conn.send(self.inbuff.pop(0))
                    self.inseq = (self.inseq + 1) % MAX_SEQ
                return

            # Finally, must be out of order; ack/store it
            if self.inseq:
                self.send_pkt(seq=seq, flags=ACK)
                self.inbuff[self.inseq] = payload

        except BrokenPipeError as e:
            log.debug("UDS connection closed by peer")
            self.reset()

    def reset(self):
        self.inseq = None
        self.outseq = random.randint(0,MAX_SEQ)
        self.inbuff = dict()
        self.outbuff = dict()

    def fin(self):
        self.send_pkt(flags=FIN)
        self.reset()

    def send_msg(self, msg):
        while len(msg) > 0:
            payload = msg[:BUF_SIZE]
            msg = msg[BUF_SIZE:]
            self.send_pkt(payload=payload)

    def retry_unackd(self):
        for k in self.outbuff.keys():
            log.debug(f"Retry on seq: {k}")
            m,f = self.outbuff[k]
            self.send_pkt(payload=m, seq=k, flags=f)

    def send_pkt(self, payload=b'', seq=None, flags=(PSH|ACK)):

        if not seq:
            seq = self.outseq
            self.outseq = (self.outseq + 1) % MAX_SEQ

        if flags & PSH == PSH or flags & FIN == FIN:
            self.outbuff[seq] = (payload, flags)

        log.debug(f"Sending message len: {len(payload)}, seq: {seq}, flags: {flags}")
        p = self.gen_raw_pkt(payload, seq, flags)
        payload = bytes(p)
        self.sendsock.send(bytes(p))

    def gen_raw_pkt(self, payload, seq, flags):
        if self.tcp:
            return Ether()/IP(dst=self.dstip)/TCP(dport=self.rawdst,
                                                  sport=self.rawsrc,
                                                  seq=seq,
                                                  flags=flags)/payload
        raw = struct.pack('=BH', flags, seq % MAX_SEQ) + payload
        return Ether()/IP(dst=self.dstip)/UDP(dport=self.rawdst,
                                              sport=self.rawsrc)/raw

    def parse_raw_pkt(self, buf):
        return Ether(buf)

    def for_me(self, p):
        if self.tcp:
            return (p.haslayer(TCP) and
                    p[TCP].dport == self.rawdst and
                    p[TCP].sport == self.rawsrc and
                    p[TCP].flags in ['F', 'PA'])
        return (p.haslayer(UDP) and
                p[UDP].dport == self.rawdst and
                p[UDP].sport == self.rawsrc)

    def get_source_addr(self):
        p = self.gen_raw_pkt(b'',0,PSH)
        return [k for k,v in psutil.net_if_addrs().items() if p.payload.src in 
                   [a.address for a in v]
               ][0]

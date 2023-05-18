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
        p = self.gen_raw_pkt(b'',0,PSH)
        self.sendsock.bind((self.iface_for_pkt(p), socket.AF_PACKET))

        self.inbuff = dict()
        self.outbuff = dict()
        self.inseq = None
        self.outseq = None

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
            if not self.inseq:
                self.inseq = seq
            log.debug(f'Expecting seq: {self.inseq}')
            self.send_pkt(seq=seq, flags=ACK)

            # Request to initialize session
            if flags & SYN == SYN:
                self.reset(seq)
                log.debug(f'Got SYNc packet... init session with seq: {seq}')

            # Ack for sent message; delete from outbuff
            elif flags & ACK == ACK and len(payload) == 0:
                log.debug(f'Ack packet for seq: {seq}')
                if seq in self.outbuff.keys():
                    self.outbuff.pop(seq)

            # Received actual message, in order, send to connected client
            elif seq == self.inseq and flags & PSH == PSH and len(payload) > 0:
                self.inseq = (self.inseq + 1) % MAX_SEQ
                conn.send(payload)

                # Now flush any pending messages
                # TODO Handle wrap around
                sorted_keys = list(self.inbuff.keys()).sort()
#               while sorted_keys[0] 
                while sorted_keys and len(sorted_keys) > 0 and sorted_keys[0] == self.inseq:
                    conn.send(self.inbuff.pop(0))
                    self.inseq = (self.inseq + 1) % MAX_SEQ
            else:
                self.inbuff[self.inseq] = payload

        except BrokenPipeError as e:
            log.debug("UDS connection closed by peer")

    def reset(self, seq=None):
        self.inbuff = dict()
        self.outbuff = dict()
        self.inseq = seq
        self.outseq = random.randint(0,MAX_SEQ)

    def init_stream(self):
        self.outseq = random.randint(0,MAX_SEQ)
        self.send_pkt(seq=self.outseq, flags=SYN)
        log.debug(f"Init stream with seq: {self.outseq}")

    def send_msg(self, msg):
        if not self.outseq:
            self.init_stream()

        while len(msg) > 0:
            payload = msg[:BUF_SIZE]
            msg = msg[BUF_SIZE:]
            self.outbuff[self.outseq] = payload
            self.send_pkt(payload, seq=self.outseq)
            self.outseq += 1

        # Re-transmit any un-ack'd messages
        for k in self.outbuff.keys():
            self.send_pkt(self.outbuff[k], seq=k)

    def send_pkt(self, msg=b'', seq=None, flags=(PSH|ACK)):
        log.debug(f"Sending message len: {len(msg)}, seq: {seq}, flags: {flags}")
        p = self.gen_raw_pkt(msg, seq, flags)
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
                    p[TCP].flags == 'PA')
        return (p.haslayer(UDP) and
                p[UDP].dport == self.rawdst and
                p[UDP].sport == self.rawsrc)

    def iface_for_pkt(self, p):
        return [k for k,v in psutil.net_if_addrs().items() if p.payload.src in 
                   [a.address for a in v]
               ][0]

#!/usr/bin/env python3

import socket

ETH_P_IP = 0x800
PF_IP = socket.ntohs(ETH_P_IP)

BUF_SIZE = 1024
MAX_SEQ = 0xFFFF
MAX_RECV = 0xFFFF

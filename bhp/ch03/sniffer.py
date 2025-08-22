#!/usr/bin/env python3
from scapy.all import sniff
def pkt(p): print(p.summary())
if __name__ == "__main__": sniff(prn=pkt, store=False)

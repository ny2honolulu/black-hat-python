#!/usr/bin/env python3
import argparse
from datetime import datetime
from scapy.all import sniff, IP, UDP, DNS, DNSRR
from scapy.layers.dns import dnsqtypes, dnstypes

def build_args():
    p = argparse.ArgumentParser(description="DNS sniffer: queries and answers")
    p.add_argument("-i","--iface", help="Interface (e.g., wlp3s0, eth0)")
    p.add_argument("-n","--count", type=int, default=0, help="Packets to capture (0 = infinite)")
    p.add_argument("-f","--filter", default="udp port 53", help='BPF filter (default: "udp port 53")')
    return p.parse_args()

def print_answers(dns):
    rr = dns.an
    for _ in range(dns.ancount or 0):
        if not isinstance(rr, DNSRR): break
        rtype = dnstypes.get(rr.type, rr.type)
        rdata = rr.rdata
        if isinstance(rdata, (bytes, bytearray)):
            try:
                rdata = rdata.decode(errors="ignore").rstrip(".")
            except Exception:
                pass
        ttl = getattr(rr, "ttl", "")
        print(f"      -> {rtype} {rdata} ttl={ttl}")
        rr = rr.payload

def main():
    args = build_args()

    def handle(pkt):
        now = datetime.now().strftime("%H:%M:%S")
        if IP in pkt and UDP in pkt and pkt.haslayer(DNS):
            dns = pkt[DNS]
            src, dst = pkt[IP].src, pkt[IP].dst
            if dns.qd:
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                qtype = dnsqtypes.get(dns.qd.qtype, dns.qd.qtype)
            else:
                qname, qtype = "(no-qname)", "?"

            if dns.qr == 0:  # Query
                print(f"[{now}] DNS? {qname} ({qtype})  {src} -> {dst}")
            else:            # Response
                print(f"[{now}] DNS! {qname} ({qtype})  {src} -> {dst}  answers={dns.ancount} rcode={dns.rcode}")
                if dns.ancount:
                    print_answers(dns)

    sniff(prn=handle, store=False, iface=args.iface, filter=args.filter, count=args.count or 0)

if __name__ == "__main__":
    main()

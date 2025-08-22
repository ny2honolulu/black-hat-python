#!/usr/bin/env python3
import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, Ether
from scapy.utils import PcapWriter

def build_args():
    p = argparse.ArgumentParser(description="Minimal Scapy sniffer with filters + pcap")
    p.add_argument("-i","--iface", help="Interface (e.g., eth0, wlp3s0). Default = auto")
    p.add_argument("-f","--filter", default="", help='BPF filter, e.g. "tcp port 80 or udp port 53"')
    p.add_argument("-n","--count", type=int, default=0, help="Packets to capture (0=inf)")
    p.add_argument("-w","--write", help="Write packets to this pcap")
    return p.parse_args()

def main():
    args = build_args()
    writer = PcapWriter(args.write, append=True, sync=True) if args.write else None

    def handle(pkt):
        if writer: writer.write(pkt)

        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] "

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if TCP in pkt:
                line += f"TCP {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport} flags={pkt[TCP].flags}"
            elif UDP in pkt:
                line += f"UDP {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
            else:
                line += f"IP  {src} -> {dst}"
        elif Ether in pkt:
            line += f"ETH {pkt[Ether].src} -> {pkt[Ether].dst}"
        else:
            line += pkt.summary()
        print(line)

        # DNS query line
        if pkt.haslayer(DNS) and pkt[DNS].qd:
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                print(f"   DNS? {qname}")
            except Exception:
                pass

        # Light HTTP peek (plaintext only)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            if b"HTTP/" in data[:8] or b"Host:" in data:
                try:
                    text = data.decode(errors="ignore")
                    first = text.splitlines()[0] if text else ""
                    host = ""
                    for ln in text.splitlines():
                        if ln.lower().startswith("host:"):
                            host = ln.split(":",1)[1].strip()
                            break
                    print(f"   HTTP: {first} Host:{host}")
                except Exception:
                    pass

    sniff(prn=handle, store=False, iface=args.iface, filter=args.filter, count=args.count or 0)

if __name__ == "__main__":
    main()

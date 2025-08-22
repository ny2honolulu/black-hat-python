#!/usr/bin/env python3
import argparse, json
from datetime import datetime
from scapy.all import sniff, IP, UDP, DNS, DNSRR
from scapy.layers.dns import dnsqtypes, dnstypes
from scapy.utils import PcapWriter

def build_args():
    p = argparse.ArgumentParser(description="DNS sniffer: queries + answers, with JSON and PCAP output")
    p.add_argument("-i","--iface", help="Interface (e.g., wlp3s0, eth0)")
    p.add_argument("-n","--count", type=int, default=0, help="Packets to capture (0 = infinite)")
    p.add_argument("-f","--filter", default="udp port 53", help='BPF filter (default: "udp port 53")')
    p.add_argument("--pcap", help="Write raw packets to this .pcap")
    p.add_argument("--json", help="Append structured events to this .jsonl file")
    return p.parse_args()

def answers_list(dns):
    out = []
    rr = dns.an
    for _ in range(int(dns.ancount or 0)):
        if not isinstance(rr, DNSRR): break
        rtype = dnstypes.get(rr.type, rr.type)
        rdata = rr.rdata
        if isinstance(rdata, (bytes, bytearray)):
            try: rdata = rdata.decode(errors="ignore").rstrip(".")
            except Exception: pass
        ttl = getattr(rr, "ttl", None)
        out.append({"type": rtype, "data": rdata, "ttl": ttl})
        rr = rr.payload
    return out

def main():
    args = build_args()
    writer = PcapWriter(args.pcap, append=True, sync=True) if args.pcap else None
    jfile = open(args.json, "a") if args.json else None

    def handle(pkt):
        if writer: writer.write(pkt)

        now = datetime.now().isoformat(timespec="seconds")
        if IP in pkt and UDP in pkt and pkt.haslayer(DNS):
            dns = pkt[DNS]
            src, dst = pkt[IP].src, pkt[IP].dst
            if dns.qd:
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                qtype = dnsqtypes.get(dns.qd.qtype, dns.qd.qtype)
            else:
                qname, qtype = "(no-qname)", "?"

            if dns.qr == 0:
                # query
                line = f"[{now}] DNS? {qname} ({qtype})  {src} -> {dst}"
                print(line)
                rec = {"ts": now, "dir": "query", "src": src, "dst": dst,
                       "qname": qname, "qtype": qtype}
            else:
                # response
                ans = answers_list(dns)
                line = f"[{now}] DNS! {qname} ({qtype})  {src} -> {dst}  answers={len(ans)} rcode={dns.rcode}"
                print(line)
                for a in ans:
                    print(f"      -> {a['type']} {a['data']} ttl={a['ttl']}")
                rec = {"ts": now, "dir": "response", "src": src, "dst": dst,
                       "qname": qname, "qtype": qtype, "rcode": int(dns.rcode), "answers": ans}

            if jfile:
                jfile.write(json.dumps(rec) + "\n")
                jfile.flush()

    try:
        sniff(prn=handle, store=False, iface=args.iface, filter=args.filter, count=args.count or 0)
    finally:
        if writer: writer.close()
        if jfile: jfile.close()

if __name__ == "__main__":
    main()

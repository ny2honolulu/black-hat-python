#!/usr/bin/env python3
import argparse, json
from datetime import datetime
from scapy.all import sniff, IP, UDP, TCP, DNS, DNSRR
from scapy.layers.dns import dnsqtypes, dnstypes
from scapy.utils import PcapWriter

def build_args():
    p = argparse.ArgumentParser(description="DNS sniffer w/ CNAME chains, NODATA reasons, JSON/PCAP logging")
    p.add_argument("-i","--iface", help="Interface (e.g., wlp3s0, eth0)")
    p.add_argument("-n","--count", type=int, default=0, help="Packets to capture (0 = infinite)")
    p.add_argument("-f","--filter", default="port 53", help='BPF filter (default: "port 53" i.e., UDP+TCP)')
    p.add_argument("--json", help="Append structured events to this .jsonl file")
    p.add_argument("--pcap", help="Write raw packets to this .pcap")
    return p.parse_args()

def iter_rr(first_rr, count):
    rr = first_rr
    for _ in range(int(count or 0)):
        if not isinstance(rr, DNSRR): break
        yield rr
        rr = rr.payload

def rr_name(rr):
    n = getattr(rr, "rrname", b"")
    if isinstance(n, (bytes, bytearray)):
        try: n = n.decode(errors="ignore").rstrip(".")
        except Exception: n = str(n)
    return n

def rr_val(rr):
    v = getattr(rr, "rdata", "")
    if isinstance(v, (bytes, bytearray)):
        try: v = v.decode(errors="ignore").rstrip(".")
        except Exception: v = str(v)
    return v

def flags_list(dns):
    out = []
    for name in ("qr","aa","tc","rd","ra","ad","cd"):
        if getattr(dns, name, 0): out.append(name.upper())
    return out

def cname_chain(ans_rrs, qname):
    """Return a CNAME chain starting at qname, plus final A/AAAA values if present."""
    # Build name -> target map for CNAMEs in Answer
    cmap = {}
    a_map, aaaa_map = {}, {}
    for rr in ans_rrs:
        t = dnstypes.get(rr.type, rr.type)
        nm = rr_name(rr)
        if t == "CNAME":
            cmap[nm] = str(rr_val(rr))
        elif t == "A":
            a_map.setdefault(nm, []).append(str(rr_val(rr)))
        elif t == "AAAA":
            aaaa_map.setdefault(nm, []).append(str(rr_val(rr)))
    chain = []
    cur = qname
    seen = set()
    while cur in cmap and cur not in seen:
        chain.append(f"{cur} -> {cmap[cur]}")
        seen.add(cur)
        cur = cmap[cur]
    # Append final A/AAAA if any
    finals = []
    if cur in a_map: finals += [f"A {ip}" for ip in a_map[cur]]
    if cur in aaaa_map: finals += [f"AAAA {ip}" for ip in aaaa_map[cur]]
    return chain, finals

def main():
    args = build_args()
    writer = PcapWriter(args.pcap, append=True, sync=True) if args.pcap else None
    jfile = open(args.json, "a") if args.json else None

    def handle(pkt):
        if not (IP in pkt and pkt.haslayer(DNS)):
            return
        dns = pkt[DNS]
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = "UDP" if UDP in pkt else ("TCP" if TCP in pkt else "?")
        if writer: writer.write(pkt)

        # Question fields
        if dns.qd:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            qtype = dnsqtypes.get(dns.qd.qtype, dns.qd.qtype)
        else:
            qname, qtype = "(no-qname)", "?"

        fl = flags_list(dns)
        fstr = ",".join(fl) if fl else "-"

        if dns.qr == 0:
            # Query
            line = f"[{now}] DNS? {qname} ({qtype})  {src} -> {dst}  proto={proto}"
            print(line)
            rec = {"ts": now, "dir":"query", "src":src, "dst":dst, "proto":proto,
                   "qname":qname, "qtype":qtype}
        else:
            # Response
            ans  = list(iter_rr(dns.an, dns.ancount))
            auth = list(iter_rr(dns.ns, dns.nscount))
            add  = list(iter_rr(dns.ar, dns.arcount))
            header = (f"[{now}] DNS! {qname} ({qtype})  {src} -> {dst}  "
                      f"answers={len(ans)} auth={len(auth)} add={len(add)} "
                      f"rcode={int(dns.rcode)} flags={fstr} proto={proto}")
            print(header)

            # Answers summary
            for rr in ans:
                t = dnstypes.get(rr.type, rr.type)
                print(f"      [ans] {rr_name(rr)} {t} {rr_val(rr)} ttl={getattr(rr,'ttl',None)}")

            # CNAME chain (if present)
            chain, finals = cname_chain(ans, qname)
            for hop in chain:
                print(f"      [cname] {hop}")
            if finals:
                print(f"      [final] {', '.join(finals)}")

            # Explain NODATA (NOERROR + 0 answers) and surface helpful extra info
            explain = None
            if dns.rcode == 0 and len(ans) == 0:
                if any(getattr(rr,"type",None) == 6 for rr in auth):  # SOA in Authority
                    explain = "NODATA (SOA in Authority: name exists, no records of this TYPE)"
                    print(f"      (explain) {explain}")
                if "TC" in fstr:
                    msg = "UDP reply truncated (TC); resolver likely retried via TCP 53"
                    explain = f"{explain}; {msg}" if explain else msg
                    print(f"      (explain) {msg}")
                # Show useful Additional records
                for rr in add:
                    t = dnstypes.get(getattr(rr,"type",None), getattr(rr,"type",None))
                    if t in ("A","AAAA","CNAME","SVCB","HTTPS"):
                        print(f"      [add ] {rr_name(rr)} {t} {rr_val(rr)}")

            rec = {
                "ts": now, "dir":"response", "src":src, "dst":dst, "proto":proto,
                "qname":qname, "qtype":qtype, "rcode": int(dns.rcode), "flags": fl,
                "answers":   [ {"name": rr_name(rr), "type": dnstypes.get(rr.type, rr.type), "data": rr_val(rr), "ttl": getattr(rr,"ttl",None)} for rr in ans ],
                "authority": [ {"name": rr_name(rr), "type": dnstypes.get(rr.type, rr.type), "data": rr_val(rr)} for rr in auth ],
                "additional":[ {"name": rr_name(rr), "type": dnstypes.get(rr.type, rr.type), "data": rr_val(rr)} for rr in add ],
                "cname_chain": chain,
                "final_addrs": finals,
                "explain": explain
            }

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

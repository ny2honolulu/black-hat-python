PY := .venv/bin/python

.PHONY: dev caps sniff-dns sniff-web chat-listen chat-client clean

dev:
	@test -d .venv || python3 -m venv .venv
	@$(PY) -m pip install --upgrade pip >/dev/null
	@$(PY) -m pip install scapy >/dev/null
	@echo "venv ready: $(PY)"

caps:
	sudo setcap cap_net_raw,cap_net_admin+eip $(shell readlink -f $(PY))
	@echo "granted NET_RAW caps to $(PY)"

sniff-dns:
	@$(PY) bhp/ch03/dns_watch.py --pcap dns.pcap --json dns.jsonl

sniff-web:
	@$(PY) bhp/ch03/sniffer.py -f "tcp port 80 or udp port 53" -w web.pcap

chat-listen:
	@$(PY) bhp/ch02/bhpnet.py -l -p 9999 -c

chat-client:
	@$(PY) bhp/ch02/bhpnet.py -t 127.0.0.1 -p 9999 -c

clean:
	rm -f *.pcap *.jsonl

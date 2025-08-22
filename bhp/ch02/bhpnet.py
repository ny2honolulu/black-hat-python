#!/usr/bin/env python3
import argparse, socket, sys, threading

def chat(sock):
    def recv_loop():
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    print("[*] Connection closed by peer.")
                    break
                sys.stdout.write(data.decode(errors="ignore"))
                sys.stdout.flush()
        except Exception as e:
            print(f"[*] recv error: {e}")
        finally:
            try: sock.shutdown(socket.SHUT_RDWR)
            except: pass
            sock.close()

    def send_loop():
        try:
            for line in sys.stdin:
                sock.sendall(line.encode())
        except Exception as e:
            print(f"[*] send error: {e}")
        finally:
            try: sock.shutdown(socket.SHUT_RDWR)
            except: pass
            sock.close()

    threading.Thread(target=recv_loop, daemon=True).start()
    send_loop()

def serve(host, port, chat_mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Listening on {host}:{port} ...")
        conn, addr = server.accept()
        print(f"[*] Connection from {addr[0]}:{addr[1]}")
        if chat_mode: chat(conn)
        else:
            data = conn.recv(65535)
            if data: print(data.decode(errors="ignore"))
            conn.close()

def client(target, port, chat_mode):
    with socket.create_connection((target, port)) as sock:
        if chat_mode: chat(sock)
        else:
            payload = sys.stdin.read()
            if payload:
                sock.sendall(payload.encode())
                resp = sock.recv(65535)
                if resp: print(resp.decode(errors="ignore"))

def main():
    p = argparse.ArgumentParser(description="Tiny netcat-like chat tool (safe)")
    p.add_argument("-t","--target", default="127.0.0.1")
    p.add_argument("-p","--port", type=int, required=True)
    p.add_argument("-l","--listen", action="store_true")
    p.add_argument("-c","--chat", action="store_true")
    p.add_argument("--host", default="0.0.0.0")
    args = p.parse_args()
    try:
        if args.listen: serve(args.host, args.port, args.chat)
        else:           client(args.target, args.port, args.chat)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

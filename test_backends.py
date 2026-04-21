import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

def run_http():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"HTTP OK\n")
    server = HTTPServer(('127.0.0.1', 9190), Handler)
    print("HTTP backend listening on 9190")
    server.serve_forever()

def run_tcp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 9191))
    server.listen(5)
    print("TCP backend listening on 9191")
    while True:
        client, addr = server.accept()
        data = client.recv(1024)
        if data:
            client.sendall(b"TCP OK\n")
        client.close()

def run_udp():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 9192))
    print("UDP backend listening on 9192")
    while True:
        data, addr = server.recvfrom(1024)
        if data:
            server.sendto(b"UDP OK\n", addr)

if __name__ == '__main__':
    threading.Thread(target=run_http, daemon=True).start()
    threading.Thread(target=run_tcp, daemon=True).start()
    threading.Thread(target=run_udp, daemon=True).start()
    
    import time
    while True:
        time.sleep(1)

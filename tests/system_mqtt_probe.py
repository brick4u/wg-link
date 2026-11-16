"""Private, bounded MQTT 3.1.1 test driver projected into the APN Pod.

Uses real CONNECT/SUBSCRIBE/QoS1 PUBLISH/PUBACK, never reconnects a held socket.
The loopback-only control endpoint is reached through kubectl exec, not a Service.
"""
import concurrent.futures
import http.server
import json
import os
import socket
import struct
import threading
import time


def text(value):
    value = value.encode()
    return struct.pack('!H', len(value)) + value


def packet(kind, payload):
    n, encoded = len(payload), b''
    while True:
        digit, n = n % 128, n // 128
        encoded += bytes([digit | (128 if n else 0)])
        if not n:
            return bytes([kind]) + encoded + payload


class Client:
    def __init__(self, ident, port, credentials, source='198.18.10.2', host='192.0.2.80'):
        self.ident, self.sequence = ident, 0
        self.socket = socket.socket()
        self.socket.settimeout(8)
        try:
            self.socket.bind((source, 0))
            self.socket.connect((host, port))
            self.identity = [list(self.socket.getsockname()), list(self.socket.getpeername())]
            self.socket.sendall(packet(0x10, text('MQTT') + bytes([4, 194]) + struct.pack('!H', 3600)
                                       + text(ident) + text(credentials['username']) + text(credentials['password'])))
            response = self.receive()
            assert response == (0x20, b'\x00\x00'), 'MQTT CONNACK rejected: ' + repr(response)
            self.topic = 'isolated/' + ident
            self.socket.sendall(packet(0x82, b'\x00\x01' + text(self.topic) + b'\x01'))
            response = self.receive()
            assert response == (0x90, b'\x00\x01\x01'), 'MQTT SUBACK rejected: ' + repr(response)
            self.roundtrip()
        except BaseException:
            self.close()
            raise

    def exact(self, n):
        value = b''
        while len(value) < n:
            part = self.socket.recv(n - len(value))
            if not part:
                raise ConnectionError('held MQTT connection closed')
            value += part
        return value

    def receive(self):
        kind, remaining, multiplier = self.exact(1)[0], 0, 1
        for _ in range(4):
            digit = self.exact(1)[0]
            remaining += (digit & 127) * multiplier
            if not digit & 128:
                if remaining > 65536:
                    raise ValueError('oversized MQTT test packet')
                return kind, self.exact(remaining)
            multiplier *= 128
        raise ValueError('invalid MQTT remaining length')

    def roundtrip(self):
        self.sequence += 1
        number = self.sequence % 65534 + 1
        payload = (self.ident + ':' + str(self.sequence)).encode()
        self.socket.sendall(packet(0x32, text(self.topic) + struct.pack('!H', number) + payload))
        ack = echo = False
        while not (ack and echo):
            kind, body = self.receive()
            if kind == 0x40:
                assert body == struct.pack('!H', number), 'unexpected PUBACK'
                ack = True
            elif kind >> 4 == 3:
                length = struct.unpack('!H', body[:2])[0]
                assert body[2:2 + length].decode() == self.topic
                offset = 2 + length
                qos = (kind >> 1) & 3
                if qos:
                    self.socket.sendall(packet(0x40, body[offset:offset + 2]))
                    offset += 2
                assert body[offset:] == payload, 'MQTT sequence mismatch'
                echo = True
            else:
                raise ValueError('unexpected MQTT packet type')
        return {'client_id': self.ident, 'socket': self.identity, 'sequence': self.sequence,
                'puback': True, 'subscribed_echo': True}

    def close(self):
        self.socket.close()


class Driver:
    def __init__(self, credentials):
        self.credentials, self.clients = credentials, {}

    def request(self, request):
        action = request['action']
        if action == 'open':
            count = request.get('count', 3)
            assert 1 <= count <= 1000
            assert not self.clients, 'close previous group first'
            started = time.monotonic()
            errors = []
            # Fixed worker cap bounds in-flight handshakes; pacing bounds start rate.
            def connect(i):
                ident = request['prefix'] + '-' + str(i)
                return Client(ident, [12101, 12201, 1883][i % 3], self.credentials)
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                futures = []
                for i in range(count):
                    futures.append(pool.submit(connect, i))
                    time.sleep(request.get('interval', 0.02))
                for future in futures:
                    try:
                        client = future.result()
                        self.clients[client.ident] = client
                    except Exception as error:
                        errors.append(type(error).__name__)
            elapsed = time.monotonic() - started
            return {'requested': count, 'established': len(self.clients), 'errors': errors,
                    'seconds': elapsed, 'established_per_second': len(self.clients) / elapsed,
                    'flows': [dict(client_id=c.ident, socket=c.identity, sequence=c.sequence)
                              for c in self.clients.values()]}
        if action == 'fresh':
            assert request['port'] in (12101, 12201, 1883)
            client = Client(request['prefix'], request['port'], self.credentials)
            try:
                return client.roundtrip()
            finally:
                client.close()
        if action == 'check':
            selected = request.get('ids', list(self.clients))
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                return list(pool.map(lambda ident: self.clients[ident].roundtrip(), selected))
        if action == 'broken':
            try:
                self.clients[request['id']].roundtrip()
            except (OSError, ValueError, AssertionError):
                return {'broken': True}
            return {'broken': False}
        if action == 'close':
            for client in self.clients.values():
                client.close()
            self.clients.clear()
            return {'closed': True}
        raise ValueError('unknown operation')


def serve():
    with open('/mqtt-auth/credentials.json') as file:
        driver = Driver(json.load(file))
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers['Content-Length'])
                assert length <= 65536
                result = driver.request(json.loads(self.rfile.read(length)))
                body = json.dumps({'ok': True, 'result': result}).encode()
                self.send_response(200)
            except Exception as error:
                body = json.dumps({'ok': False, 'error': type(error).__name__, 'detail': str(error)[:256]}).encode()
                self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    # Serial request handling prevents concurrent operations on an MQTT socket.
    http.server.HTTPServer(('127.0.0.1', 18083), Handler).serve_forever()


if __name__ == '__main__':
    serve()

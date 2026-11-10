#!/usr/bin/env python3
"""Compare emitted TLS structure with an independent Xray binary on loopback."""
import argparse
import hashlib
import json
import socket
import subprocess
import threading
import time
from pathlib import Path


def exact(conn, count):
    data = b''
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise EOFError('incomplete TLS record')
        data += part
    return data


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def capture(binary, xray, fingerprint, work):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(10)
        remote, local = listener.getsockname()[1], port()
        uuid = 'b831381d-6324-4d53-ad4f-8cda48b30811'
        if xray:
            config = {'inbounds': [{'listen': '127.0.0.1', 'port': local, 'protocol': 'socks'}],
                      'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': remote, 'users': [{'id': uuid, 'encryption': 'none'}]}]},
                                     'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'localhost', 'alpn': ['h2', 'http/1.1'], 'fingerprint': fingerprint}}}]}
        else:
            config = {'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': local}],
                      'outbounds': [{'type': 'vless', 'server': '127.0.0.1', 'server_port': remote, 'uuid': uuid,
                                     'tls': {'enabled': True, 'server_name': 'localhost', 'alpn': ['h2', 'http/1.1'], 'utls': {'enabled': True, 'fingerprint': fingerprint}}}]}
        label = ('xray-' if xray else 'candidate-') + fingerprint
        path = work / (label + '.json')
        path.write_text(json.dumps(config))
        with (work / (label + '.log')).open('w') as log:
            process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=log, stderr=log)
            def request():
                try:
                    for _ in range(100):
                        try:
                            conn = socket.create_connection(('127.0.0.1', local), .2)
                            break
                        except OSError:
                            time.sleep(.05)
                    else:
                        return
                    with conn:
                        conn.settimeout(10)
                        conn.sendall(b'\x05\x01\x00')
                        assert exact(conn, 2) == b'\x05\x00'
                        conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbbpayload')
                        conn.recv(1024)
                except (OSError, EOFError):
                    pass
            worker = threading.Thread(target=request)
            worker.start()
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(5)
                    hello = b''
                    while len(hello) < 4 or len(hello) < 4 + int.from_bytes(hello[1:4], 'big'):
                        header = exact(conn, 5)
                        assert header[0] == 22, header
                        hello += exact(conn, int.from_bytes(header[3:5], 'big'))
                    (work / (label + '.bin')).write_bytes(hello)
                    return hello
            finally:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                worker.join(11)


def normalize(raw):
    def word(data):
        return int.from_bytes(data, 'big')
    def grease(value):
        return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255
    def words(data):
        return [0x0a0a if grease(word(data[i:i+2])) else word(data[i:i+2]) for i in range(0, len(data), 2)]
    cursor = 38
    cursor += 1 + raw[cursor]
    size = word(raw[cursor:cursor+2]); cursor += 2
    ciphers = words(raw[cursor:cursor+size]); cursor += size
    size = raw[cursor]; cursor += 1
    compression = raw[cursor:cursor+size].hex(); cursor += size
    size = word(raw[cursor:cursor+2]); cursor += 2
    assert len(raw) == cursor + size
    extensions = {}
    shares = []
    while cursor < len(raw):
        typ, size = word(raw[cursor:cursor+2]), word(raw[cursor+2:cursor+4]); cursor += 4
        body = raw[cursor:cursor+size]; cursor += size
        if grease(typ):
            continue
        if typ == 51:
            offset = 2
            while offset < len(body):
                group, length = word(body[offset:offset+2]), word(body[offset+2:offset+4])
                shares.append([0x0a0a if grease(group) else group, length])
                offset += 4 + length
            extensions[str(typ)] = shares
        elif typ in (10, 13):
            extensions[str(typ)] = words(body[2:])
        elif typ == 43:
            extensions[str(typ)] = words(body[1:])
        elif typ == 65037:
            # ECH GREASE is randomized; presence is compared, not its bytes.
            extensions[str(typ)] = 'GREASE'
        else:
            extensions[str(typ)] = body.hex()
    return {'ciphers': ciphers, 'compression': compression, 'extensions': extensions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xray', required=True, type=Path)
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    results = []
    for fingerprint in ('chrome', 'firefox', 'safari'):
        reference = normalize(capture(args.xray.resolve(), True, fingerprint, args.work))
        candidate = normalize(capture(args.client.resolve(), False, fingerprint, args.work))
        result = {'fingerprint': fingerprint, 'match': reference == candidate, 'reference': reference, 'candidate': candidate}
        results.append(result)
        print(fingerprint, 'PASS' if result['match'] else 'FAIL', flush=True)
    (args.work / 'results.json').write_text(json.dumps({'binaries': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.xray, args.client)}, 'results': results}, indent=2))
    assert all(result['match'] for result in results), 'ClientHello structure mismatch'


if __name__ == '__main__':
    main()

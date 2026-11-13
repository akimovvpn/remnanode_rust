import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import contextlib
import socket
import socketserver
import struct
import threading
import time


SCRIPT = Path(__file__).resolve().parents[1] / 'fix_client_dns.py'


def client_config():
    return {
        'dns': {
            'tag': 'dns_in', 'hosts': {'private.test': '10.0.0.1'},
            'servers': [
                {'address': 'https://common.dot.dns.yandex.net/dns-query',
                 'domains': ['geosite:category-ru'], 'skipFallback': True},
                'https://8.8.8.8/dns-query', 'tcp://1.1.1.1', 'localhost',
            ],
        },
        'inbounds': [{'tag': 'apps-socks', 'protocol': 'socks', 'settings': {'udp': True}},
                     {'tag': 'apps-http', 'protocol': 'http'}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'},
                      {'tag': 'blocked', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': ['dns_in'], 'ip': ['8.8.8.8', '1.1.1.1'], 'outboundTag': 'proxy'},
            {'type': 'field', 'inboundTag': ['dns_in'], 'outboundTag': 'direct'},
        ]},
        'unrelated': {'secret': 'preserve me'},
    }


class ClientDNSFixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('fix_client_dns', SCRIPT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_intercepts_app_dns_before_existing_routes_without_changing_split(self):
        original = client_config()
        before = copy.deepcopy(original)
        fixed = self.module.patch_config(original)
        self.assertEqual(original, before)
        self.assertEqual(fixed['routing']['rules'][0], {
            'type': 'field', 'inboundTag': ['apps-socks', 'apps-http'],
            'network': 'tcp,udp', 'port': '53', 'outboundTag': 'dns-out',
        })
        self.assertEqual(fixed['routing']['rules'][1:], original['routing']['rules'])
        self.assertEqual(fixed['outbounds'][:-1], original['outbounds'])
        self.assertEqual(fixed['outbounds'][-1], {'tag': 'dns-out', 'protocol': 'dns', 'settings': {}})
        self.assertEqual(fixed['dns']['servers'], original['dns']['servers'][:-1])
        self.assertEqual(fixed['dns']['hosts'], original['dns']['hosts'])
        self.assertEqual(fixed['unrelated'], original['unrelated'])
        self.assertEqual(self.module.patch_config(fixed), fixed)

    def test_conflicting_tag_is_preserved_and_a_unique_tag_is_used(self):
        original = client_config()
        original['outbounds'].extend([{'tag': 'dns-out', 'protocol': 'blackhole'},
                                      {'tag': 'dns-out-1', 'protocol': 'freedom'}])
        fixed = self.module.patch_config(original)
        self.assertEqual(fixed['outbounds'][:-1], original['outbounds'])
        self.assertEqual(fixed['routing']['rules'][0]['outboundTag'], 'dns-out-2')
        self.assertEqual(self.module.patch_config(fixed), fixed)

    def test_rejects_malformed_or_unsafe_to_patch_configs(self):
        changes = [
            ('dns', None), ('dns', {}), ('dns', {'servers': ['localhost']}),
            ('dns', {'servers': [None]}), ('dns', {'servers': [{'address': []}]}),
            ('inbounds', []), ('inbounds', [{'protocol': 'socks'}]),
            ('outbounds', []), ('outbounds', [None]), ('outbounds', [{}]),
            ('routing', []), ('routing', {'rules': [None]}),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                config = client_config()
                config[key] = value
                with self.assertRaises(ValueError):
                    self.module.patch_config(config)
        with self.assertRaises(ValueError):
            self.module.patch_config([])

    def test_object_localhost_is_removed_and_missing_routing_is_created(self):
        config = client_config()
        config['dns']['servers'][-1] = {'address': 'localhost', 'skipFallback': True}
        del config['routing']
        fixed = self.module.patch_config(config)
        self.assertEqual(len(fixed['dns']['servers']), 3)
        self.assertEqual(len(fixed['routing']['rules']), 1)

    def test_cli_writes_private_new_file_without_overwriting_input_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'client.json', Path(directory) / 'fixed.json'
            original = json.dumps(client_config())
            source.write_text(original)
            run = subprocess.run([sys.executable, str(SCRIPT), str(source), str(output)], capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(source.read_text(), original)
            self.assertEqual(json.loads(output.read_text())['routing']['rules'][0]['outboundTag'], 'dns-out')
            if os.name == 'posix':
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            for target in [source, output]:
                run = subprocess.run([sys.executable, str(SCRIPT), str(source), str(target)], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertNotIn(b'preserve me', run.stderr)
            self.assertEqual(source.read_text(), original)

    def test_cli_rejects_ambiguous_json_and_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'client.json', Path(directory) / 'fixed.json'
            for raw in ['{"dns": {}, "dns": {}}', '{bad json', '[]']:
                source.write_text(raw)
                run = subprocess.run([sys.executable, str(SCRIPT), str(source), str(output)], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(output.exists())
                self.assertEqual(sorted(x.name for x in Path(directory).iterdir()), ['client.json'])


def receive_exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError('fixture connection closed')
        data += part
    return data


def dns_query(domain, qtype=1):
    name = b''.join(bytes([len(label)]) + label.encode('ascii') for label in domain.split('.')) + b'\0'
    return struct.pack('!6H', 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', qtype, 1)


@contextlib.contextmanager
def dns_server(address):
    queries = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            query = receive_exact(self.request, struct.unpack('!H', receive_exact(self.request, 2))[0])
            offset, labels = 12, []
            while query[offset]:
                size = query[offset]
                labels.append(query[offset + 1:offset + 1 + size].decode('ascii'))
                offset += size + 1
            queries.append('.'.join(labels))
            question = query[12:offset + 5]
            response = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question
            response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton(address)
            self.request.sendall(struct.pack('!H', len(response)) + response)

    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
        thread.start()
        try:
            yield server.server_address[1], queries
        finally:
            server.shutdown()
            thread.join()


@contextlib.contextmanager
def xray_client(binary, config, directory):
    path = Path(directory) / 'client.json'
    path.write_text(json.dumps(config))
    with (Path(directory) / 'xray.log').open('wb') as log:
        process = subprocess.Popen([binary, 'run', '-config', str(path)], stdout=log, stderr=log)
        try:
            port = config['inbounds'][0]['port']
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise AssertionError('Xray fixture failed: ' + (Path(directory) / 'xray.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError('Xray fixture never listened')
                    time.sleep(0.02)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@contextlib.contextmanager
def socks_dns(port, udp=True):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as control:
        control.sendall(b'\x05\x01\x00')
        if receive_exact(control, 2) != b'\x05\x00':
            raise AssertionError('SOCKS fixture greeting failed')
        if udp:
            control.sendall(b'\x05\x03\x00\x01' + b'\0' * 6)
        else:
            control.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('77.88.8.8') + b'\x00\x35')
        reply = receive_exact(control, 10)
        if reply[:4] != b'\x05\x00\x00\x01':
            raise AssertionError('SOCKS fixture request failed')
        if not udp:
            yield control
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                datagram.connect((socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0]))
                datagram.settimeout(5)
                yield datagram


@unittest.skipUnless(os.environ.get('XRAY_BINARY'), 'set XRAY_BINARY to the pinned Go Xray 26.11.9 binary')
class ClientDNSGoTests(unittest.TestCase):
    def test_application_dns_is_hijacked_and_ru_global_resolvers_remain_split(self):
        binary = os.environ['XRAY_BINARY']
        version = subprocess.check_output([binary, 'version'], text=True)
        self.assertIn('Xray 26.11.9 ', version)
        with dns_server('192.0.2.11') as (ru_port, ru_queries), dns_server('198.51.100.22') as (global_port, global_queries), tempfile.TemporaryDirectory() as directory:
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            config = {
                'log': {'loglevel': 'warning'},
                'dns': {'tag': 'dns_in', 'queryStrategy': 'UseIPv4', 'servers': [
                    {'address': f'tcp://127.0.0.1:{ru_port}', 'domains': ['domain:sample.ru'], 'skipFallback': True},
                    f'tcp://127.0.0.1:{global_port}']},
                'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': port,
                              'protocol': 'socks', 'settings': {'udp': True, 'ip': '127.0.0.1'}}],
                'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'},
                              {'tag': 'direct', 'protocol': 'freedom', 'settings': {
                                  'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}],
                'routing': {'rules': [{'type': 'field', 'inboundTag': ['dns_in'], 'outboundTag': 'direct'}]},
            }
            destination = b'\0\0\0\x01' + socket.inet_aton('77.88.8.8') + b'\0\x35'
            with xray_client(binary, config, directory) as socks:
                with socks_dns(socks) as udp:
                    udp.settimeout(0.3)
                    udp.send(destination + dns_query('sample.ru'))
                    with self.assertRaises(socket.timeout):
                        udp.recv(65536)
                self.assertEqual((ru_queries, global_queries), ([], []))
            spec = importlib.util.spec_from_file_location('fix_client_dns', SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            fixed = module.patch_config(config)
            with xray_client(binary, fixed, directory) as socks:
                with socks_dns(socks) as udp:
                    for domain, expected in [('sample.ru', '192.0.2.11'), ('sample.com', '198.51.100.22')]:
                        udp.send(destination + dns_query(domain))
                        reply = udp.recv(65536)[10:]
                        self.assertEqual(reply[:2], b'\x12\x34')
                        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 1)
                        self.assertEqual(socket.inet_ntoa(reply[-4:]), expected)
                    udp.send(destination + dns_query('sample.ru', 15))
                    reply = udp.recv(65536)[10:]
                    self.assertEqual(struct.unpack('!H', reply[6:8])[0], 0)
                    self.assertEqual(reply[3] & 15, 0, 'default non-IP response is empty success')
                with socks_dns(socks, udp=False) as tcp:
                    query = dns_query('tcp.sample.ru')
                    tcp.sendall(struct.pack('!H', len(query)) + query)
                    reply = receive_exact(tcp, struct.unpack('!H', receive_exact(tcp, 2))[0])
                    self.assertEqual(socket.inet_ntoa(reply[-4:]), '192.0.2.11')
            self.assertEqual(ru_queries, ['sample.ru', 'tcp.sample.ru'])
            self.assertEqual(global_queries, ['sample.com'])


if __name__ == '__main__':
    unittest.main()

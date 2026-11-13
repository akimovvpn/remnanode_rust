#!/usr/bin/env python3
"""Linux server-only bulk benchmark, using a pinned Go Xray client for both cores.

Requires Python 3.9+, openssl, and release Rust/Go binaries. All traffic and
credentials are disposable loopback fixtures; no external service is contacted.
"""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import statistics
import struct
import subprocess
import threading
import time

USER = '6b1f2b9e-2f7e-4f43-9d2a-1c1d2e3f4a5b'
SNI = 'target.test'
BLOCK = bytes(range(256)) * 256


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError(f'EOF after {len(data)} of {count} bytes')
        data.extend(chunk)
    return bytes(data)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def ready(process, port):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(f'process exited: {process.args}')
        try:
            with socket.create_connection(('127.0.0.1', port), .1):
                return
        except OSError:
            time.sleep(.025)
    raise TimeoutError(f'port {port} did not open')


def proc_sample(pid):
    # comm may contain spaces or parentheses; fields after its final ')' start at 3.
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
    return {
        'cpu_seconds': (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
        'rss_kib': int(status['VmRSS'].split()[0]),
        'hwm_kib': int(status['VmHWM'].split()[0]),
    }


class Target:
    def __init__(self, tls=None):
        self.tls = tls
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.errors = []
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            conn.settimeout(90)
            with conn:
                if self.tls:
                    conn = self.tls.wrap_socket(conn, server_side=True)
                with conn:
                    while True:
                        # Calibration probes and port checks close before a request.
                        first = conn.recv(8)
                        if not first:
                            return
                        count = struct.unpack('!Q', first + exact(conn, 8 - len(first)))[0]
                        if count > 16 * 1024**3 or count % len(BLOCK):
                            raise ValueError(f'invalid fixture byte count {count}')
                        conn.sendall(b'OK')
                        for _ in range(count // len(BLOCK)):
                            if exact(conn, len(BLOCK)) != BLOCK:
                                raise ValueError('upload payload corrupted')
                        for _ in range(count // len(BLOCK)):
                            conn.sendall(BLOCK)
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            # REALITY's calibration connection ends after the TLS ServerHello.
            pass
        except Exception as error:
            self.errors.append(repr(error))


def transfer(sock, count):
    sock.sendall(struct.pack('!Q', count))
    if exact(sock, 2) != b'OK':
        raise ValueError('fixture acknowledgement changed')
    for _ in range(count // len(BLOCK)):
        sock.sendall(BLOCK)
    for _ in range(count // len(BLOCK)):
        if exact(sock, len(BLOCK)) != BLOCK:
            raise ValueError('download payload corrupted')


def tunnel(socks_port, target_port, cert=None):
    sock = socket.create_connection(('127.0.0.1', socks_port), 90)
    sock.sendall(b'\x05\x01\x00')
    if exact(sock, 2) != b'\x05\x00':
        raise ValueError('SOCKS authentication failed')
    sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target_port))
    reply = exact(sock, 4)
    if reply != b'\x05\x00\x00\x01':
        raise ValueError(f'unexpected SOCKS response {reply!r}')
    exact(sock, 6)  # Go's SOCKS listener returns an IPv4 bind address and port.
    if cert:
        ctx = ssl.create_default_context(cafile=str(cert))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        sock = ctx.wrap_socket(sock, server_hostname=SNI)
        if sock.version() != 'TLSv1.3':
            raise ValueError('inner TLS is not TLS 1.3')
    return sock


def config(vision, server_port, socks_port, target_port, private, public):
    flow = 'xtls-rprx-vision' if vision else ''
    inbound = {'listen': '127.0.0.1', 'port': server_port, 'protocol': 'vless',
               'settings': {'clients': [{'id': USER, 'flow': flow}], 'decryption': 'none'}}
    outbound = {'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1',
                'port': server_port, 'users': [{'id': USER, 'encryption': 'none', 'flow': flow}]}]}}
    if vision:
        inbound['streamSettings'] = {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'target': f'127.0.0.1:{target_port}', 'serverNames': [SNI], 'privateKey': private,
            'shortIds': ['0123abcd']}}
        outbound['streamSettings'] = {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'serverName': SNI, 'password': public, 'shortId': '0123abcd', 'fingerprint': 'chrome'}}
    server = {'log': {'loglevel': 'error'}, 'inbounds': [inbound], 'outbounds': [{
        'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
    client = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': socks_port,
              'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
    return server, client


def run_case(binary, go, vision, count, directory, target, cert, private, public):
    server_port, socks_port = free_port(), free_port()
    while socks_port == server_port:
        socks_port = free_port()
    server, client = config(vision, server_port, socks_port, target.port, private, public)
    directory.mkdir()
    for name, value in [('server', server), ('client', client)]:
        (directory / f'{name}.json').write_text(json.dumps(value))
    with contextlib.ExitStack() as stack:
        logs = [stack.enter_context((directory / f'{name}.log').open('w')) for name in ['server', 'client']]
        processes = []
        try:
            for executable, name, log in [(binary, 'server', logs[0]), (go, 'client', logs[1])]:
                process = subprocess.Popen([str(executable), 'run', '-config', str(directory / f'{name}.json')],
                                           stdout=log, stderr=log)
                processes.append(process)
                ready(process, server_port if name == 'server' else socks_port)
            server_process = processes[0]
            sock = stack.enter_context(tunnel(socks_port, target.port, cert if vision else None))
            transfer(sock, 4 * 1024**2)  # Exclude target calibration, connection setup and direct-copy switch.
            pre = []
            for _ in range(20):
                pre.append(proc_sample(server_process.pid)['rss_kib'])
                time.sleep(.01)
            samples = []
            stop = threading.Event()

            def sample():
                while not stop.wait(.01):
                    samples.append(proc_sample(server_process.pid)['rss_kib'])

            sampler = threading.Thread(target=sample)
            sampler.start()
            before = proc_sample(server_process.pid)
            started = time.monotonic()
            try:
                transfer(sock, count)
            finally:
                elapsed = time.monotonic() - started
                after = proc_sample(server_process.pid)
                stop.set()
                sampler.join()
            post = []
            for _ in range(20):
                post.append(proc_sample(server_process.pid)['rss_kib'])
                time.sleep(.01)
            client_log = (directory / 'client.log').read_text()
            direct_up = any('XtlsPadding ' in line and line.endswith(' 2') for line in client_log.splitlines())
            direct_down = 'command 2' in client_log
            if vision and not (direct_up and direct_down):
                raise RuntimeError('Go client did not confirm both Vision direct-copy directions')
            if target.errors:
                raise RuntimeError(f'fixture target errors: {target.errors}')
            cpu = after['cpu_seconds'] - before['cpu_seconds']
            return {'server_cpu_seconds': round(cpu, 6), 'elapsed_seconds': round(elapsed, 6),
                    'application_upload_bytes': count, 'application_download_bytes': count,
                    'cpu_seconds_per_gib': round(cpu / (2 * count / 1024**3), 6),
                    'rss_warm_kib': statistics.median(pre), 'rss_steady_kib': statistics.median(post),
                    'rss_sampled_peak_kib': max(samples + [before['rss_kib'], after['rss_kib']]),
                    'rss_process_lifetime_hwm_kib': after['hwm_kib'],
                    'vision_direct_up_confirmed': direct_up, 'vision_direct_down_confirmed': direct_down}
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--mib', type=int, default=512, help='application bytes in EACH direction')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or args.mib < 1 or args.rounds < 1:
        parser.error('Linux, positive MiB and positive rounds are required')
    args.rust, args.go = args.rust.resolve(), args.go.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    cert, key = args.output / 'target.pem', args.output / 'target.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-days', '1', '-subj', f'/CN={SNI}', '-addext', f'subjectAltName=DNS:{SNI}',
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = tls.maximum_version = ssl.TLSVersion.TLSv1_3
    tls.set_ecdh_curve('X25519')
    tls.set_alpn_protocols(['h2', 'http/1.1'])
    tls.load_cert_chain(cert, key)
    plain, secure = Target(), Target(tls)
    private = base64.urlsafe_b64encode(bytes((i * 37 + 11) % 256 for i in range(32))).decode().rstrip('=')
    keys = subprocess.check_output([str(args.go), 'x25519', '-i', private], text=True)
    public = next(line.split(': ', 1)[1] for line in keys.splitlines() if line.startswith('Password'))
    result = {'environment': {'uname': platform.uname()._asdict(), 'python': platform.python_version(),
              'openssl': ssl.OPENSSL_VERSION, 'go': subprocess.check_output([str(args.go), 'version'], text=True),
              'rust_binary': str(args.rust),
              'rust_version': subprocess.check_output([str(args.rust), 'version'], text=True),
              'binary_sha256': {name: hashlib.sha256(binary.read_bytes()).hexdigest()
                                for name, binary in [('rust', args.rust), ('go', args.go)]},
              'cpu_clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
              'rss_sample_interval_ms': 10, 'warmup_bytes_each_direction': 4 * 1024**2,
              'denominator': 'application upload + download bytes; excludes warmup, framing, TLS and REALITY overhead'},
              'measurements': []}
    for vision in [False, True]:
        for round_number in range(1, args.rounds + 1):
            # Alternate the first server to reduce drift bias.
            order = [('rust', args.rust), ('go', args.go)]
            if round_number % 2 == 0:
                order.reverse()
            for name, binary in order:
                label = f'{"vision-tls13" if vision else "plain-vless"}-{round_number}-{name}'
                print(f'START {label}', flush=True)
                row = {'case': 'vision-tls13' if vision else 'plain-vless', 'round': round_number, 'server': name}
                row.update(run_case(binary, args.go, vision, args.mib * 1024**2, args.output / label,
                                    secure if vision else plain, cert, private, public))
                result['measurements'].append(row)
                (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps(row), flush=True)
    plain.listener.close()
    secure.listener.close()


if __name__ == '__main__':
    main()

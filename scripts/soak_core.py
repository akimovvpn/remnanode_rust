#!/usr/bin/env python3
"""Bounded local traffic soak; no user config or external destinations are used."""
import argparse
import asyncio
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ID = bytes.fromhex('01010101010101010101010101010101')


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def header(target, udp=False):
    return b'\0' + ID + bytes([0, 2 if udp else 1]) + target.to_bytes(2, 'big') + b'\x01\x7f\0\0\x01'


async def echo(reader, writer):
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.transport.sendto(data, peer)


async def xhttp(node, target, payload):
    reader, writer = await asyncio.open_connection('127.0.0.1', node)
    try:
        body = header(target) + payload
        request = (f'POST /soak/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\n'
                   f'X-Padding: {"x" * 100}\r\nConnection: close\r\n\r\n').encode() + body
        writer.write(request)
        await writer.drain()
        head = await reader.readuntil(b'\r\n\r\n')
        assert head.startswith(b'HTTP/1.1 200'), head
        result = bytearray()
        if b'transfer-encoding: chunked' in head.lower():
            while True:
                size = int((await reader.readline()).split(b';')[0].strip(), 16)
                if size == 0:
                    break
                result += await reader.readexactly(size)
                assert await reader.readexactly(2) == b'\r\n'
        else:
            result += await reader.read()
        assert result == b'\0\0' + payload, 'XHTTP payload changed'
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def run(args):
    loop = asyncio.get_running_loop()
    tcp = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = tcp.sockets[0].getsockname()[1]
    udp, _ = await loop.create_datagram_endpoint(EchoUDP, local_addr=('127.0.0.1', 0))
    udp_target = udp.get_extra_info('sockname')[1]
    nodes = [port(), port()]
    while nodes[0] == nodes[1]:
        nodes[1] = port()
    base = {'listen': '127.0.0.1', 'protocol': 'vless', 'settings': {'clients': [{'id': ID.hex()}], 'decryption': 'none'}}
    config = {'log': {'loglevel': 'none'}, 'inbounds': [
        base | {'tag': 'raw', 'port': nodes[0]},
        base | {'tag': 'xhttp', 'port': nodes[1], 'streamSettings': {'network': 'xhttp', 'xhttpSettings': {
            'path': '/soak/', 'mode': 'stream-one', 'extra': {'xPaddingBytes': '100-100', 'xPaddingPlacement': 'header', 'xPaddingObfsMode': True}}}},
    ], 'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
    with tempfile.TemporaryDirectory(prefix='rcore-soak-') as tmp:
        path = Path(tmp) / 'config.json'
        path.write_text(json.dumps(config))
        with (Path(tmp) / 'core.log').open('w+') as log:
            child = subprocess.Popen([str(Path(args.binary).resolve()), 'run', '-config', str(path)], stdout=log, stderr=log)
            counts = {'tcp': 0, 'udp': 0, 'xhttp': 0}
            rss = []
            start = time.monotonic()
            try:
                for node in nodes:
                    for _ in range(100):
                        try:
                            _, writer = await asyncio.open_connection('127.0.0.1', node)
                            writer.close()
                            await writer.wait_closed()
                            break
                        except OSError:
                            assert child.poll() is None, 'core exited during startup'
                            await asyncio.sleep(.05)
                    else:
                        raise AssertionError('core did not listen')
                deadline = time.monotonic() + args.seconds

                async def worker(index):
                    kind = ['tcp', 'udp', 'xhttp'][index % 3]
                    while time.monotonic() < deadline:
                        assert child.poll() is None, 'core exited under load'
                        payload = (f'{index}:{counts[kind]}:'.encode() + bytes(range(256)) * 16)
                        if kind == 'xhttp':
                            await asyncio.wait_for(xhttp(nodes[1], target, payload), 5)
                            counts[kind] += 1
                        else:
                            reader, writer = await asyncio.open_connection('127.0.0.1', nodes[0])
                            try:
                                writer.write(header(udp_target if kind == 'udp' else target, kind == 'udp'))
                                for n in range(8):
                                    writer.write((len(payload).to_bytes(2, 'big') if kind == 'udp' else b'') + payload)
                                    await writer.drain()
                                    if n == 0:
                                        assert await asyncio.wait_for(reader.readexactly(2), 5) == b'\0\0'
                                    if kind == 'udp':
                                        assert int.from_bytes(await asyncio.wait_for(reader.readexactly(2), 5), 'big') == len(payload)
                                    assert await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload, 'payload changed'
                                    counts[kind] += 1
                                    await asyncio.sleep(.02)
                            finally:
                                writer.close()
                                with contextlib.suppress(ConnectionError):
                                    await writer.wait_closed()
                        await asyncio.sleep(.05)

                async def monitor():
                    while time.monotonic() < deadline:
                        value = await asyncio.to_thread(subprocess.run, ['ps', '-o', 'rss=', '-p', str(child.pid)], capture_output=True, text=True)
                        assert value.returncode == 0 and value.stdout.strip(), 'core exited'
                        rss.append(int(value.stdout.strip()))
                        await asyncio.sleep(min(5, max(.01, deadline - time.monotonic())))

                await asyncio.wait_for(asyncio.gather(*(worker(i) for i in range(args.clients)), monitor()), args.seconds + 15)
                assert all(counts.values()), counts
                print(json.dumps({'seconds': round(time.monotonic() - start, 2), 'clients': args.clients,
                                  'exchanges': counts, 'rss_kib_first': rss[0], 'rss_kib_last': rss[-1], 'rss_kib_peak_sampled': max(rss)}))
            except BaseException:
                log.seek(0)
                print(log.read()[-8000:])
                raise
            finally:
                child.terminate()
                try:
                    await asyncio.to_thread(child.wait, timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    await asyncio.to_thread(child.wait)
    udp.close()
    tcp.close()
    await tcp.wait_closed()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--clients', type=int, default=32)
    args = parser.parse_args()
    if not (1 <= args.seconds <= 86400 and 3 <= args.clients <= 256):
        parser.error('seconds must be 1..86400 and clients 3..256')
    asyncio.run(run(args))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Real mutual-TLS, JWT, HTTP and Xray smoke test. Uses only stdlib + openssl."""
import argparse
import base64
import gzip
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time


def run(*args, data=None):
    return subprocess.run(args, input=data, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def certificates(folder):
    def openssl(*args):
        return run("openssl", *args)
    ca_key, ca = folder / "ca.key", folder / "ca.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-days", "2", "-subj", "/CN=Smoke CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    jwt_key = folder / "jwt.key"
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(jwt_key))
    jwt_pub = openssl("pkey", "-in", str(jwt_key), "-pubout").decode()
    canon = lambda pem: "".join(line.strip() for line in pem.splitlines() if not line.startswith("-----"))
    ikm = (canon(jwt_pub) + canon(ca.read_text())).encode()
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    out = hmac.new(prk, b"rw-v1\x01", hashlib.sha256).digest()[:22]
    sni = f'{out[:16].hex()}.{out[16:21].hex()}.{["com", "net", "org", "io", "dev", "app"][out[21] % 6]}'
    for role, usage in [("node", "serverAuth"), ("client", "clientAuth")]:
        key, cert, csr, ext = [folder / f"{role}.{suffix}" for suffix in ("key", "pem", "csr", "ext")]
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={role}")
        ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:{sni},IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "2", "-extfile", str(ext))
    payload = {"caCertPem": ca.read_text(), "jwtPublicKey": jwt_pub, "nodeCertPem": (folder / "node.pem").read_text(), "nodeKeyPem": (folder / "node.key").read_text()}
    return payload, sni, jwt_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--xray", required=True)
    args = parser.parse_args()
    binary, xray = str(Path(args.binary).resolve()), str(Path(args.xray).resolve())
    with tempfile.TemporaryDirectory(prefix="remnanode-smoke-") as tmp:
        folder = Path(tmp)
        payload, sni, jwt_key = certificates(folder)
        node_port, api_port, inbound_port = port(), port(), port()
        now = int(time.time())
        unsigned = f'{b64(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}")}.{b64(json.dumps({"exp": now + 300}).encode())}'
        signature = run("openssl", "dgst", "-sha256", "-sign", str(jwt_key), data=unsigned.encode())
        token = f"Bearer {unsigned}.{b64(signature)}"
        env = os.environ | {"NODE_PORT":str(node_port), "SECRET_KEY":base64.b64encode(json.dumps(payload).encode()).decode(), "SNI_VERIFICATION":"true", "XRAY_BINARY":xray, "STATE_DIR":str(folder / "state"), "XRAY_API_ENDPOINT":f"http://127.0.0.1:{api_port}"}
        env.pop("DISABLE_HASHED_SET_CHECK", None)
        client = ssl.create_default_context(cafile=str(folder / "ca.pem"))
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        client.load_cert_chain(str(folder / "client.pem"), str(folder / "client.key"))

        def request(method, path, value=None, auth=token, context=client, server_name=sni, compressed=False):
            body = json.dumps(value).encode() if value is not None else b""
            if compressed:
                body = gzip.compress(body)
            headers = [f"{method} {path} HTTP/1.1", "Host: localhost", "Connection: close", "Content-Type: application/json", f"Content-Length: {len(body)}"]
            if auth:
                headers.append(f"Authorization: {auth}")
            if compressed:
                headers.append("Content-Encoding: gzip")
            with socket.create_connection(("127.0.0.1", node_port), timeout=15) as tcp:
                with context.wrap_socket(tcp, server_hostname=server_name) as tls:
                    tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    data = response.read()
                    return response.status, json.loads(data) if data else None

        log = open(folder / "node.log", "w+")
        process = subprocess.Popen([binary], env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(f"Node exited during startup:\n{log.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", node_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Node startup timed out")
            no_cert = ssl.create_default_context(cafile=str(folder / "ca.pem"))
            try:
                request("GET", "/node/xray/healthcheck", context=no_cert)
            except (ssl.SSLError, ConnectionError, http.client.HTTPException):
                pass
            else:
                raise AssertionError("mTLS accepted a connection without client certificate")
            try:
                request("GET", "/node/xray/healthcheck", server_name="wrong.example")
            except (ssl.SSLError, ConnectionError, http.client.HTTPException):
                pass
            else:
                raise AssertionError("SNI verifier accepted the wrong name")
            legacy = ssl.create_default_context(cafile=str(folder / "ca.pem"))
            legacy.maximum_version = ssl.TLSVersion.TLSv1_2
            legacy.load_cert_chain(str(folder / "client.pem"), str(folder / "client.key"))
            try:
                request("GET", "/node/xray/healthcheck", context=legacy)
            except (ssl.SSLError, ConnectionError, http.client.HTTPException):
                pass
            else:
                raise AssertionError("Server accepted TLS 1.2")
            assert request("GET", "/node/xray/healthcheck", auth=None)[0] == 401
            assert request("GET", "/node/xray/healthcheck", auth="Bearer invalid")[0] == 401
            status, data = request("GET", "/node/xray/healthcheck")
            assert status == 200 and data["response"]["isAlive"] is True, (status, data)
            assert request("POST", "/node/handler/add-user", ["not an object"])[0] == 400
            assert request("POST", "/node/stats/get-users-stats", {"reset":"false"})[0] == 400
            config = {"inbounds":[{"tag":"smoke", "listen":"127.0.0.1", "port":inbound_port, "protocol":"vless", "settings":{"clients":[], "decryption":"none"}}], "outbounds":[{"tag":"direct", "protocol":"freedom"}]}
            start = {"internals":{"hashes":{"emptyConfig":"smoke", "inbounds":[{"tag":"smoke", "usersCount":0, "hash":"0000000000000000"}]}}, "xrayConfig":config}
            status, data = request("POST", "/node/xray/start", start, compressed=True)
            assert status == 200 and data["response"]["isStarted"] is True, (status, data)
            assert request("GET", "/node/xray/healthcheck")[1]["response"]["xrayInternalStatusCached"] is True
            user_id = "550e8400-e29b-41d4-a716-446655440000"
            status, data = request("POST", "/node/handler/add-user", {"data":[{"type":"vless", "tag":"smoke", "username":"smoke-user", "uuid":user_id, "flow":""}], "hashData":{"vlessUuid":user_id}})
            assert status == 200 and data["response"]["success"] is True, (status, data)
            status, data = request("POST", "/node/stats/get-users-stats", {"reset":False})
            assert status == 200 and isinstance(data["response"]["users"], list), (status, data)
            status, data = request("POST", "/node/handler/remove-user", {"username":"smoke-user", "hashData":{"vlessUuid":user_id}})
            assert status == 200 and data["response"]["success"] is True, (status, data)
            status, data = request("GET", "/node/stats/get-system-stats")
            assert status == 200 and data["response"]["xrayInfo"] is not None, (status, data)
            assert request("GET", "/node/xray/stop")[1]["response"]["isStopped"] is True
            assert request("GET", "/node/xray/healthcheck")[1]["response"]["xrayInternalStatusCached"] is False
            mode = (folder / "state" / "config.json").stat().st_mode & 0o777
            assert mode == 0o600, oct(mode)
            print("PASS: mutual TLS, TLS1.3, SNI, RS256, auth failures, request validation, gzip, real Xray start/add/stats/remove/stop, private config")
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()


if __name__ == "__main__":
    main()

# Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
# SPDX-License-Identifier: GPL-3.0-only

"""Independent Unix JSON subscriber and process lifecycle regression.

Run: python3 src/tests/telemetry/headless.py BINARY [--isolation-peer NW2_BINARY]
Uses only the public IPC contract and Python's standard library.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

KEY = "0123456789abcdef0123456789abcdef"
DEADLINE = 10


def wait_for(predicate):
    deadline = time.monotonic() + DEADLINE
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("process readiness deadline elapsed")


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        assert chunk, "unexpected EOF"
        result.extend(chunk)
    return bytes(result)


def read_message(sock):
    length = struct.unpack("!I", exact(sock, 4))[0]
    assert 0 < length <= 65536
    return json.loads(exact(sock, length))


def next_kind(sock, kind):
    deadline = time.monotonic() + DEADLINE
    while time.monotonic() < deadline:
        message = read_message(sock)
        if message["type"] == kind:
            return message["data"]
    raise AssertionError(f"missing IPC message: {kind}")


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(DEADLINE)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise AssertionError("service did not shut down within its deadline")


def main():
    assert os.name == "posix", "this regression uses Unix sockets"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isolation-peer", type=Path,
                        help="optional NW2 executable for cross-namespace regression")
    args = parser.parse_args()
    current = str(args.binary.resolve())
    baseline = str(args.isolation_peer.resolve()) if args.isolation_peer else None
    processes = []
    ipc = None
    with tempfile.TemporaryDirectory(prefix="n3-", dir="/tmp") as tmp:
        env = dict(os.environ, TMPDIR=tmp, NOW_TELEMETRY_INTERVAL="250ms",
                   TOKIO_WORKER_THREADS="2")
        nw2_directory = Path(tmp) / f"nowhere-telemetry-{os.getuid()}"
        nw3_directory = Path(tmp) / f"nowhere-telemetry-nw3-{os.getuid()}"
        try:
            def spawn(binary, url):
                process = subprocess.Popen([binary, url], env=env,
                                           stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
                processes.append(process)
                return process

            legacy = None
            if baseline:
                legacy = spawn(baseline, f"portal://{KEY}@127.0.0.1:{reserve_port()}?log=none")
                legacy_records = wait_for(lambda: list(nw2_directory.glob("*.json")))
                legacy_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in legacy_records}
            port = reserve_port()
            portal = spawn(current, f"portal://{KEY}@127.0.0.1:{port}?log=none")
            records = wait_for(lambda: list(nw3_directory.glob("*.json")))
            assert nw3_directory.stat().st_mode & 0o777 == 0o700
            record = json.loads(records[0].read_text())
            assert record["protocol"] == "nowhere.telemetry.3"
            assert record["instance"]["pid"] == portal.pid
            assert records[0].stat().st_mode & 0o777 == 0o600
            assert Path(record["endpoint"]).parent == nw3_directory
            assert Path(record["endpoint"]).stat().st_mode & 0o777 == 0o600
            ipc = socket.socket(socket.AF_UNIX)
            ipc.settimeout(DEADLINE)
            ipc.connect(record["endpoint"])
            hello = next_kind(ipc, "hello")
            assert hello["instance"]["telemetry_protocol"] == record["protocol"]
            assert hello["instance"]["pid"] == portal.pid
            assert hello["instance"]["role"] == "portal"
            assert KEY not in json.dumps(hello)
            snapshot = next_kind(ipc, "snapshot")
            assert snapshot["egress_online"] is None
            assert snapshot["lifecycle"] in ("STARTING", "READY")
            assert "config_summary" not in hello["instance"]
            assert "lifecycle" not in hello
            # Reconnection receives the same instance identity and current state.
            ipc.close()
            ipc = socket.socket(socket.AF_UNIX)
            ipc.settimeout(DEADLINE)
            ipc.connect(record["endpoint"])
            assert next_kind(ipc, "hello")["instance"]["id"] == hello["instance"]["id"]
            assert read_message(ipc)["type"] == "snapshot"

            pin = subprocess.check_output([current, "fingerprint",
                f"nowhere://{KEY}@127.0.0.1:{port}"], env=env, timeout=DEADLINE,
                stderr=subprocess.PIPE).decode().strip()
            assert len(pin) == 64
            ingress = reserve_port()
            vector = spawn(current, f"vector://{KEY}@127.0.0.1:{port}"
                           f"?net=tcp&in=127.0.0.1:{ingress}&pin={pin}&log=none")
            wait_for(lambda: len(list(nw3_directory.glob("*.json"))) == 2)
            target = socket.socket()
            target.bind(("127.0.0.1", 0))
            target.listen(1)
            target.settimeout(DEADLINE)
            payload = b"nw3-headless-known-bytes" * 128
            echo_errors = []

            def echo():
                try:
                    connection, _ = target.accept()
                    with connection:
                        connection.settimeout(DEADLINE)
                        while True:
                            data = connection.recv(65536)
                            if not data:
                                break
                            connection.sendall(data)
                except Exception as error:
                    echo_errors.append(error)

            worker = threading.Thread(target=echo, daemon=True)
            worker.start()
            with wait_for(lambda: connect_ready(ingress)) as flow:
                flow.settimeout(DEADLINE)
                flow.sendall(b"\x05\x01\x00")
                assert exact(flow, 2) == b"\x05\x00"
                flow.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                             + struct.pack("!H", target.getsockname()[1]))
                reply = exact(flow, 10)
                assert reply[:4] == b"\x05\x00\x00\x01"
                flow.sendall(payload)
                flow.shutdown(socket.SHUT_WR)
                assert exact(flow, len(payload)) == payload
                assert flow.recv(1) == b""
            worker.join(DEADLINE)
            target.close()
            assert not worker.is_alive() and not echo_errors
            started = next_kind(ipc, "access_start")
            finished = next_kind(ipc, "access_finish")
            assert finished["sequence"] > started["sequence"]
            assert finished["id"] == started["id"]
            assert finished["result"] == "success"
            assert started["carrier"] == "tls"
            assert set(started) == {"sequence", "id", "timestamp_ms", "protocol", "target", "carrier"}
            assert set(finished) == {"sequence", "id", "timestamp_ms", "result"}
            assert KEY not in json.dumps([started, finished])
            deadline = time.monotonic() + DEADLINE
            while time.monotonic() < deadline:
                snapshot = next_kind(ipc, "snapshot")
                if snapshot["tcp_active"] == 0 and snapshot["tcp_upload_bytes"] == len(payload):
                    break
            assert snapshot["tcp_active"] == 0
            assert snapshot["tcp_upload_bytes"] == len(payload)
            assert snapshot["tcp_download_bytes"] == len(payload)
            assert snapshot["tls_upload_bytes"] == len(payload)
            assert snapshot["tls_download_bytes"] == len(payload)
            assert not any(key.endswith(("_up", "_down")) for key in snapshot)
            vector_record = next(json.loads(p.read_text()) for p in nw3_directory.glob("*.json")
                                 if json.loads(p.read_text())["instance"]["pid"] == vector.pid)
            with socket.socket(socket.AF_UNIX) as observer:
                observer.settimeout(DEADLINE)
                observer.connect(vector_record["endpoint"])
                assert next_kind(observer, "hello")["instance"]["role"] == "vector"
                deadline = time.monotonic() + DEADLINE
                while time.monotonic() < deadline:
                    observed = next_kind(observer, "snapshot")
                    if observed["tcp_upload_bytes"] == len(payload) and observed["tcp_active"] == 0:
                        break
                assert observed["tcp_upload_bytes"] == len(payload), observed
                assert observed["tcp_download_bytes"] == len(payload)
                assert observed["egress_online"] is None
            # Any input closes the connection, even a partial frame.
            ipc.sendall(b"\x00")
            while ipc.recv(65536):
                pass
            ipc.close()
            ipc = socket.socket(socket.AF_UNIX)
            ipc.settimeout(DEADLINE)
            ipc.connect(record["endpoint"])
            next_kind(ipc, "hello")
            assert read_message(ipc)["type"] == "snapshot"
            status = subprocess.check_output([current, "status"], env=env, timeout=DEADLINE,
                                             stderr=subprocess.PIPE).decode()
            assert f"PORTAL · PID {portal.pid}" in status
            assert f"VECTOR · PID {vector.pid}" in status
            if legacy is not None:
                assert f"PORTAL · PID {legacy.pid}" not in status
            assert KEY not in status
            help_output = subprocess.check_output([current], env=env, timeout=DEADLINE,
                                                  stderr=subprocess.PIPE).decode()
            assert "USAGE" in help_output and "nowhere tui" not in help_output
            removed = subprocess.run([current, "tui"], env=env, timeout=DEADLINE,
                                     capture_output=True)
            assert removed.returncode == 1 and b"unknown command" in removed.stderr
            assert b"terminal" not in removed.stderr
            ipc.close()
            ipc = None
            stop(vector)
            stop(portal)
            assert not list(nw3_directory.glob("*.json"))
            assert not list(nw3_directory.glob("*.sock"))
            if legacy is not None:
                assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in nw2_directory.glob("*.json")} == legacy_hashes
                assert legacy.poll() is None
            idle = subprocess.check_output([current, "status"], env=env, timeout=DEADLINE).decode()
            assert "IDLE" in idle
            print(json.dumps({"headless": "passed", "passive_reconnection": "passed",
                              "extra_input_disconnect": "passed",
                              "known_logical_bytes_each_direction": len(payload),
                              "namespace_isolation": "passed" if legacy is not None else "not run", "cleanup": "passed"}))
        finally:
            if ipc is not None:
                ipc.close()
            for process in reversed(processes):
                stop(process)


def connect_ready(port):
    try:
        return socket.create_connection(("127.0.0.1", port), timeout=0.2)
    except OSError:
        return None


if __name__ == "__main__":
    main()

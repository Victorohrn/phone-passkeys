#!/usr/bin/env python3
"""Exercises the native host over its stdio protocol without a browser.

It pings the host, starts a request, prints the QR code (as an image in the
terminal when `qrencode` is installed, otherwise as the raw FIDO:/ string), and
then either waits for a result from your phone or cancels after --wait seconds.

Examples:
  tools/host-smoke-test.py                      # ping + QR for https://webauthn.io, cancel after 20s
  tools/host-smoke-test.py --wait 120           # leave the QR up long enough to scan it with a phone
  tools/host-smoke-test.py --cmd create         # registration flow instead of sign-in
"""
import argparse
import json
import os
import pathlib
import select
import shutil
import struct
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_HOST = ROOT / "host" / "target" / "release" / "phone-passkeys-host"


def send(proc, obj):
    data = json.dumps(obj).encode()
    proc.stdin.write(struct.pack("@I", len(data)) + data)
    proc.stdin.flush()


def read_exact(stream, n, timeout):
    buf = b""
    deadline = time.monotonic() + timeout
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            return None
        chunk = stream.read(n - len(buf))
        if not chunk:
            return b"" if not buf else None
        buf += chunk
    return buf


def recv(proc, timeout):
    header = read_exact(proc.stdout, 4, timeout)
    if header is None:
        return None
    if header == b"":
        return "EOF"
    (length,) = struct.unpack("@I", header)
    body = read_exact(proc.stdout, length, timeout)
    if not body:
        return "EOF"
    return json.loads(body)


def show_qr(fido):
    print(f"\nFIDO string: {fido}\n")
    if shutil.which("qrencode"):
        subprocess.run(["qrencode", "-t", "ANSIUTF8", "-l", "H", fido], check=False)
    else:
        print("(install `qrencode` to render the QR code in the terminal)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=str(DEFAULT_HOST), help="path to the host binary")
    ap.add_argument("--origin", default="https://webauthn.io")
    ap.add_argument("--rp-id", default=None, help="defaults to the origin's host")
    ap.add_argument("--cmd", choices=["get", "create"], default="get")
    ap.add_argument("--wait", type=float, default=20, help="seconds to wait for the phone before cancelling")
    ap.add_argument("--log", default="debug", help="PHONE_PASSKEYS_LOG filter for the host")
    args = ap.parse_args()

    rp_id = args.rp_id or args.origin.split("://", 1)[1].split(":", 1)[0]
    env = dict(os.environ, PHONE_PASSKEYS_LOG=args.log)
    proc = subprocess.Popen([args.host], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0, env=env)
    failures = 0

    def expect(what, msg):
        nonlocal failures
        ok = isinstance(msg, dict) and msg.get("type") == what
        print(f"[{'ok' if ok else 'FAIL'}] expected {what!r}: {json.dumps(msg)[:300] if isinstance(msg, dict) else msg}")
        if not ok:
            failures += 1
        return ok

    send(proc, {"type": "ping"})
    expect("pong", recv(proc, 15))

    challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    if args.cmd == "get":
        options = {"challenge": challenge, "rpId": rp_id, "timeout": 120000, "userVerification": "preferred"}
    else:
        options = {
            "rp": {"id": rp_id, "name": "Smoke test"},
            "user": {"id": "c21va2UtdGVzdC11c2Vy", "name": "smoke-test", "displayName": "Smoke test"},
            "challenge": challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 120000,
            "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
            "attestation": "none",
        }
    send(proc, {"type": "start", "id": "smoke-1", "cmd": args.cmd, "origin": args.origin, "options": options})

    deadline = time.monotonic() + args.wait
    got_qr = False
    final = None
    while time.monotonic() < deadline:
        msg = recv(proc, max(0.1, deadline - time.monotonic()))
        if msg is None:
            continue
        if msg == "EOF":
            print("[FAIL] host closed stdout unexpectedly")
            failures += 1
            break
        kind = msg.get("type")
        if kind == "qr" and not got_qr:
            got_qr = expect("qr", msg)
            show_qr(msg["fido"])
            print(f"QR SVG size: {len(msg.get('svg', ''))} bytes")
            print(f"Waiting up to {args.wait:.0f}s for a phone... (Ctrl-C to stop)")
        elif kind == "state":
            print(f"[state] {msg.get('state')} {msg.get('detail') or ''}")
        elif kind in ("result", "error"):
            final = msg
            print(f"[{kind}] {json.dumps(msg)[:600]}")
            break
        else:
            print(f"[msg] {json.dumps(msg)[:300]}")

    if not got_qr:
        print("[FAIL] no QR code was produced")
        failures += 1

    if final is None:
        send(proc, {"type": "cancel", "id": "smoke-1"})
        msg = recv(proc, 10)
        if expect("error", msg) and msg.get("name") != "AbortError":
            print(f"[FAIL] expected AbortError after cancel, got {msg.get('name')}")
            failures += 1

    proc.stdin.close()
    try:
        code = proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        code = "killed (did not exit after stdin closed)"
        failures += 1
    print(f"host exit: {code}")
    print("SMOKE TEST", "PASSED" if failures == 0 else f"FAILED ({failures} problem(s))")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()

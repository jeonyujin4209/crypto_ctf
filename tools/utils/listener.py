"""
Local shim for `cryptohack.org`'s `utils.listener` module.

CryptoHack ships challenge files like `13388.py` that end with:

    import builtins; builtins.Challenge = Challenge
    listener.start_server(port=13388)

Their `utils.listener` module is not public. This shim is a minimal reimplementation
that lets us run the chall.py files unmodified, on localhost, so we can develop &
verify our exploit POCs against a known-protocol oracle. The FLAG inside the chall
files is a placeholder string — the same exploit, pointed at socket.cryptohack.org
on the right port, retrieves the real flag.

Wire protocol observed in CryptoHack chall files:
  * Server, on each new TCP connection, instantiates a fresh `Challenge()`.
  * If the instance has `before_input` (a string), the server sends it (newline-
    terminated, JSON-wrapped or plain — varies). We send it as plain text.
  * Then it loops: read a JSON object terminated by newline, call
    `instance.challenge(parsed)`, and write the returned dict as JSON + newline.
  * On JSON parse failure, send `{"error": "invalid input"}`.
  * Closing the socket ends the session.

Usage:
    PYTHONPATH=tools python "cryptohack/.../13388.py"

This module also lets you set the bind host via env var $CRYPTOHACK_HOST
(default 127.0.0.1) so you can expose to LAN if needed.
"""

import builtins
import json
import os
import socket
import socketserver
import sys
import traceback


def _get_challenge_class():
    cls = getattr(builtins, "Challenge", None)
    if cls is None:
        raise RuntimeError(
            "No Challenge class found. The chall.py file should set "
            "builtins.Challenge = Challenge before calling start_server."
        )
    return cls


class _ChallengeHandler(socketserver.StreamRequestHandler):
    # Bigger read buffer; some chall files send chunky inputs.
    rbufsize = 1 << 16
    wbufsize = 0

    def handle(self):
        peer = self.client_address
        sys.stderr.write(f"[listener] connection from {peer}\n")
        try:
            instance = _get_challenge_class()()
        except Exception:
            sys.stderr.write("[listener] failed to construct Challenge:\n")
            traceback.print_exc()
            return

        # before_input greeting (plain text, if present)
        before = getattr(instance, "before_input", None)
        if before:
            try:
                self.wfile.write(before.encode() if isinstance(before, str) else before)
            except (BrokenPipeError, ConnectionResetError):
                return

        while True:
            try:
                line = self.rfile.readline()
            except (ConnectionResetError, OSError):
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8", errors="replace"))
            except Exception as e:
                resp = {"error": f"invalid JSON: {e}"}
            else:
                try:
                    resp = instance.challenge(msg)
                except SystemExit:
                    raise
                except Exception:
                    sys.stderr.write("[listener] challenge() raised:\n")
                    traceback.print_exc()
                    resp = {"error": "internal error"}

            if resp is None:
                resp = {}
            try:
                self.wfile.write((json.dumps(resp, default=str) + "\n").encode())
            except (BrokenPipeError, ConnectionResetError):
                break

        sys.stderr.write(f"[listener] {peer} disconnected\n")


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(port, host=None):
    """Bind a TCP server on (host, port) and serve Challenge instances forever."""
    if host is None:
        host = os.environ.get("CRYPTOHACK_HOST", "127.0.0.1")
    server = _ReusableTCPServer((host, int(port)), _ChallengeHandler)
    sys.stderr.write(f"[listener] serving on {host}:{port}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[listener] shutting down\n")
        server.shutdown()
        server.server_close()

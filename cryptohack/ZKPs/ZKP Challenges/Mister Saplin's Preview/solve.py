"""
Mister Saplin's Preview (60pts) — Merkle TOCTOU via thread race

The balance check runs in a BACKGROUND THREAD. The main thread proceeds
immediately after spawning it, and only reads `self.balance_validated`
(set to None at request start) to decide whether to return the requested
nodes. Since the thread hasn't finished yet, `balance_validated` is still
None, and the condition `!= False` passes — so we receive the nodes FREE.

One shot: request all 4 layer-1 nodes (would cost 4*50=200, balance=99).
With the race we get them anyway. Hash them pairwise to reconstruct
layer 2, hash those two to get the root.
"""
import json
import socket
import time
from hashlib import sha256
from ast import literal_eval

HOST = "socket.cryptohack.org"
PORT = 13414


def hash256(data):
    return sha256(data).digest()


def merge(a, b):
    return hash256(a + b)


def recv_line(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(4096)
        if not c:
            break
        buf += c
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def main():
    sock = socket.create_connection((HOST, PORT))
    greet = recv_line(sock)
    print(f"[*] greet: {greet.strip()}")

    # Race: request a HUGE count to slow the background thread (long loop).
    # The main thread will return the (truncated) slice before the thread's
    # loop finishes and flips balance_validated to False.
    HUGE = 100_000_000
    send_json(sock, {"option": "get_nodes", "nodes": f"1,{HUGE}"})
    resp = recv_line(sock)
    print(f"[1] {resp[:200]}")
    data = json.loads(resp)

    msg = data["msg"]
    # msg format: str([['hexhash', ...]])
    nodes_list = literal_eval(msg)
    layer_nodes = [bytes.fromhex(h) for h in nodes_list[0]]
    print(f"[+] got {len(layer_nodes)} nodes")

    # Build up to root
    if len(layer_nodes) == 4:  # layer 1
        layer2 = [merge(layer_nodes[0], layer_nodes[1]),
                  merge(layer_nodes[2], layer_nodes[3])]
        root = merge(layer2[0], layer2[1])
    elif len(layer_nodes) == 8:  # layer 0
        layer1 = [merge(layer_nodes[i], layer_nodes[i+1]) for i in (0, 2, 4, 6)]
        layer2 = [merge(layer1[0], layer1[1]), merge(layer1[2], layer1[3])]
        root = merge(layer2[0], layer2[1])
    else:
        print(f"[!] unexpected node count: {len(layer_nodes)}")
        return
    print(f"[+] root = {root.hex()}")

    send_json(sock, {"option": "do_proof", "root": root.hex()})
    final = recv_line(sock)
    print(f"[+] {final}")
    sock.close()


if __name__ == "__main__":
    main()

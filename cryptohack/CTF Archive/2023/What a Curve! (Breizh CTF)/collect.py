"""Connect to challenge, dump session_data.json (ct1 + N queries) for solve.sage."""
import socket, json

HOST = "archive.cryptohack.org"
PORT = 39003
N_QUERIES = 4

def recvline(s):
    buf = b""
    while not buf.endswith(b"\n"):
        ch = s.recv(1)
        if not ch:
            break
        buf += ch
    return buf

def main():
    s = socket.socket()
    s.connect((HOST, PORT))
    ct1_hex = recvline(s).strip().decode()
    print(f"[*] ct1 ({len(ct1_hex)//2} bytes): {ct1_hex[:80]}...")

    queries = []
    for i in range(N_QUERIES):
        recvline(s)  # prompt "Enter your message :"
        msg = b"\x00" * 112
        s.sendall(msg.hex().encode() + b"\n")
        resp = recvline(s).strip().decode()
        print(f"[*] query {i}: {resp[:64]}...")
        queries.append(resp)

    with open("session_data.json", "w") as f:
        json.dump({"ct1": ct1_hex, "queries": queries}, f)
    print("[+] saved session_data.json")
    s.close()

if __name__ == "__main__":
    main()

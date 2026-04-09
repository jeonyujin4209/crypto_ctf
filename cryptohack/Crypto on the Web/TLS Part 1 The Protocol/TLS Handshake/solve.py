from scapy.all import rdpcap, IP, TCP, Raw

packets = rdpcap("cryptohack.org.pcapng")
target_ip = "178.62.74.206"

# Parse TLS records sent by server
def parse_tls_records(data):
    """Yields (content_type, version, payload) for each TLS record."""
    i = 0
    while i + 5 <= len(data):
        ctype = data[i]
        version = (data[i+1], data[i+2])
        length = int.from_bytes(data[i+3:i+5], "big")
        if i + 5 + length > len(data):
            break
        payload = data[i+5:i+5+length]
        yield (ctype, version, payload)
        i += 5 + length

# Reassemble TCP stream from server -> client
server_data = b""
for p in packets:
    if IP in p and TCP in p and p[IP].src == target_ip and Raw in p:
        server_data += bytes(p[Raw].load)

# Find ServerHello (handshake type 2 inside content_type 22 - Handshake)
for ctype, version, payload in parse_tls_records(server_data):
    if ctype == 22:  # Handshake
        # Handshake message: 1 byte type, 3 bytes length
        j = 0
        while j + 4 <= len(payload):
            htype = payload[j]
            hlen = int.from_bytes(payload[j+1:j+4], "big")
            hbody = payload[j+4:j+4+hlen]
            if htype == 2:  # ServerHello
                # ServerHello body: legacy_version (2) + random (32) + ...
                random = hbody[2:34]
                print("Server Random (hex):", random.hex())
                print(f"Flag: crypto{{{random.hex()}}}")
            j += 4 + hlen
        break  # only first handshake

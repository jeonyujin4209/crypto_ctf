from scapy.all import rdpcap, IP

packets = rdpcap("cryptohack.org.pcapng")
print(f"Total packets: {len(packets)}")

# CryptoHack server IP is 178.62.74.206 per README
target_ip = "178.62.74.206"
count = 0
for p in packets:
    if IP in p and p[IP].dst == target_ip:
        count += 1

print(f"Packets received by {target_ip} (cryptohack.org): {count}")

import socket
try:
    s = socket.create_connection(("socket.cryptohack.org", 13416), timeout=5)
    print("connected")
    s.close()
except Exception as e:
    print("FAIL:", e)

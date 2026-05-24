"""Raw TCP client for the-black-talon protocol exploration."""
import socket, threading, queue, time, re, sys


class Conn:
    def __init__(self, host="127.0.0.1", port=31337):
        self.s = socket.create_connection((host, port))
        self.s.settimeout(0.05)
        self.buf = b""
        self.q = queue.Queue()
        self.lines = []
        self.dead = False
        # Filter: callable(str)->bool. If set, only matching lines enter queue.
        self.line_filter = None
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self.dead:
            try:
                data = self.s.recv(65536)
                if not data:
                    self.dead = True
                    return
                self.buf += data
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    s = line.decode("utf-8", "replace")
                    if self.line_filter is None or self.line_filter(s):
                        # Cap to avoid OOM. If queue is full, drop oldest first.
                        if self.q.qsize() >= 10000:
                            try: self.q.get_nowait()
                            except queue.Empty: pass
                        self.q.put(s)
            except socket.timeout:
                continue
            except OSError:
                self.dead = True
                return

    def send(self, line: str):
        assert "\n" not in line
        self.s.sendall((line + "\n").encode())

    def recv(self, timeout=2.0):
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self, max_wait=0.3):
        out = []
        end = time.time() + max_wait
        while time.time() < end:
            try:
                out.append(self.q.get(timeout=max(0.01, end - time.time())))
            except queue.Empty:
                break
        return out

    def recv_until(self, pred, timeout=5.0):
        end = time.time() + timeout
        out = []
        while time.time() < end:
            try:
                line = self.q.get(timeout=max(0.01, end - time.time()))
            except queue.Empty:
                continue
            out.append(line)
            if pred(line):
                return out
        return out

    def close(self):
        self.dead = True
        try:
            self.s.close()
        except OSError:
            pass


def connect_as(name, host="127.0.0.1", port=31337):
    c = Conn(host, port)
    welcome = c.recv(2)
    assert welcome == "WELCOME", welcome
    c.send(f"CONNECT {name}")
    r = c.recv(2)
    assert r and r.startswith("NEWUSER "), r
    pwd = r.split(" ", 1)[1]
    return c, pwd


def parse_msg(line):
    # MSGFROM <channel> <user> <message...>
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


if __name__ == "__main__":
    c, pwd = connect_as("test_user")
    print("password:", pwd)
    c.send("JOIN testchan")
    print(c.recv(2))
    c.send("PEEK testchan")
    print(c.recv(2))
    c.send("GOODBYE")
    print(c.recv(2))
    c.close()

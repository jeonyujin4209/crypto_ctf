from pwn import *
import json
import random

USE_LOCAL = False
HOST = "socket.cryptohack.org" if not USE_LOCAL else "localhost"
PORT = 13403


def json_recv(r):
    """Receive a line, strip any prefix text before JSON, and parse."""
    line = r.recvline().decode().strip()
    log.info(f"Received: {line}")
    # CryptoHack listener prepends 'before_send' text before the JSON value
    # Find the start of JSON (object, array, string, or number)
    for i, c in enumerate(line):
        if c in '{["0123456789-':
            try:
                return json.loads(line[i:])
            except json.JSONDecodeError:
                continue
    # If no JSON found, the line might be a prompt — read the next line
    line2 = r.recvline().decode().strip()
    log.info(f"Received (2nd): {line2}")
    for i, c in enumerate(line2):
        if c in '{["0123456789-':
            try:
                return json.loads(line2[i:])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"Cannot parse JSON from: {line} / {line2}")


def json_send(r, obj):
    r.sendline(json.dumps(obj).encode())


def extract_hex(data):
    """Extract a hex value from a JSON response, regardless of key name."""
    if isinstance(data, str):
        return int(data, 16)
    if isinstance(data, dict):
        for k, v in data.items():
            if k in ("error", "flag"):
                continue
            if isinstance(v, str) and (v.startswith("0x") or all(c in "0123456789abcdef" for c in v)):
                try:
                    return int(v, 16)
                except ValueError:
                    pass
    raise ValueError(f"Cannot extract hex from: {data}")


def solve():
    """
    Attack using p-adic logarithm.

    Choose n = q^2, g = 1 + q.

    Then g^q mod q^2:
      (1+q)^q = sum C(q,k) q^k
      k=0: 1
      k=1: q*q = q^2 ≡ 0 mod q^2
      k>=2: q^k ≡ 0 mod q^2
    So g^q ≡ 1 mod q^2. Constraint satisfied.

    h = g^x mod q^2 = (1+q)^x mod q^2 = 1 + x*q mod q^2

    Recovery: x = ((h - 1) mod q^2) / q mod q
    """
    r = remote(HOST, PORT)

    # Step 1: Receive q
    # Server sends: "Prime generated: " + hex(q) on one line
    # Then prompt: "Send integers (g,n) such that pow(g,q,n) = 1: " on next line
    data = json_recv(r)
    q = extract_hex(data)
    # Consume the prompt line
    try:
        prompt = r.recvline(timeout=2)
        log.info(f"Prompt: {prompt.decode().strip()}")
    except:
        pass
    log.info(f"q = {q.bit_length()} bits")

    # Step 2: Set up p-adic DLP
    n = q * q
    g = 1 + q

    assert pow(g, q, n) == 1
    assert g >= 2
    assert n >= 2
    log.success("Parameters verified: pow(g, q, n) == 1")

    # Step 3: Send g, n
    json_send(r, {"g": hex(g), "n": hex(n)})

    # Step 4: Receive h
    # Server sends: "Generated my public key: " + hex(h)
    # Then prompt: "What is my private key: "
    data = json_recv(r)
    if isinstance(data, dict) and "error" in data:
        log.error(f"Server error: {data['error']}")
        r.close()
        return
    h = extract_hex(data)
    try:
        prompt = r.recvline(timeout=2)
        log.info(f"Prompt: {prompt.decode().strip()}")
    except:
        pass
    log.info(f"h = {h.bit_length()} bits")

    # Step 5: Recover x using p-adic logarithm
    # h = 1 + x*q mod q^2
    # => x = ((h - 1) mod q^2) // q
    h_mod = h % n
    x = ((h_mod - 1) % n) // q
    x = x % q
    log.success(f"Recovered x = {hex(x)[:50]}...")

    # Step 6: Send x
    json_send(r, {"x": hex(x)})

    # Step 7: Get flag
    data = json_recv(r)
    if "flag" in data:
        log.success(f"FLAG: {data['flag']}")
    else:
        log.error(f"Failed: {data}")

    r.close()


def local_test():
    """Test the p-adic approach locally with a synthetic challenge."""
    log.info("=== LOCAL TEST ===")
    from Crypto.Util.number import getPrime

    q = getPrime(512)
    log.info(f"q = {q.bit_length()} bits")

    n = q * q
    g = 1 + q

    assert pow(g, q, n) == 1
    log.success(f"pow(g, q, n) = 1 verified")

    # Test many random x values
    successes = 0
    trials = 100
    for i in range(trials):
        x_secret = random.randint(0, q)
        h = pow(g, x_secret, n)

        # Recover
        h_mod = h % n
        x_recovered = ((h_mod - 1) % n) // q % q

        if x_recovered == x_secret:
            successes += 1
        elif x_secret == q and x_recovered == 0:
            # x=q maps to same as x=0 (order q)
            successes += 1
        else:
            log.error(f"  Trial {i}: FAIL x_secret={x_secret}, x_recovered={x_recovered}")

    log.info(f"Results: {successes}/{trials} correct")
    if successes == trials:
        log.success("ALL TESTS PASSED!")
    else:
        log.error(f"FAILED: {trials - successes} failures")


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        local_test()
    else:
        solve()

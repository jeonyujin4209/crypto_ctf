import hmac
import hashlib
import struct

from math import ceil


HASH_ALG = hashlib.sha384
HASH_LEN = HASH_ALG().digest_size


def tls_HMAC(k, b, algorithm):
    return bytearray(hmac.new(k, b, algorithm).digest())


def HKDF_expand(prk, info, length, algorithm):
    hash_len = algorithm().digest_size
    t = bytearray()
    okm = bytearray()
    for i in range(1, ceil(length / hash_len)+2):
        t = tls_HMAC(prk, t + info + bytearray([i]), algorithm)
        okm += t
    return okm[:length]


def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    hkdfLabel = bytearray()
    hkdfLabel += struct.pack('>H', length)
    seq = bytearray(b"tls13 ") + label
    hkdfLabel += bytearray([len(seq)]) + seq
    seq = hashValue
    hkdfLabel += bytearray([len(seq)]) + seq

    return HKDF_expand(secret, hkdfLabel, length, algorithm)


def verify_data(finished_key, transcript, hash_alg):
    transcript_hash = hash_alg(transcript).digest()
    return tls_HMAC(finished_key, transcript_hash, hash_alg)


client_hello = bytes.fromhex("""
?
        """)

server_hello = bytes.fromhex("""
?
        """)

server_encrypted_extensions = bytes.fromhex("""
?
        """)

server_certificate_message = bytes.fromhex("""
?
        """)

server_certificateverify_message = bytes.fromhex("""
?
        """)

server_finished = bytes.fromhex("""
?
        """)


client_handshake_traffic_secret = bytes.fromhex("?")
finished_key = HKDF_expand_label(
    client_handshake_traffic_secret, b"finished", b"", HASH_LEN, HASH_ALG)

transcript = client_hello + server_hello + \
    server_encrypted_extensions + server_certificate_message + \
    server_certificateverify_message + server_finished

client_finished = verify_data(finished_key, transcript, HASH_ALG).hex()
print(client_finished)


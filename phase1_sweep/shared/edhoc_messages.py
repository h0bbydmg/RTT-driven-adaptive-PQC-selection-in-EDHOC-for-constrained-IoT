import os
import cbor2

def build_msg1(kem_id: int, g_x: bytes) -> bytes:
    c_i = os.urandom(1)
    msg = [0, kem_id, g_x, c_i, kem_id]
    return cbor2.dumps(msg)

def parse_msg1(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {
        "method":  msg[0],
        "kem_id":  msg[1],
        "g_x":     msg[2],
        "c_i":     msg[3],
    }

def build_msg2(kem_id: int, g_y: bytes, ciphertext_kem: bytes) -> bytes:
    c_r = os.urandom(1)
    ciphertext_2 = os.urandom(16)   # simulated EDHOC CIPHERTEXT_2
    msg = [g_y, c_r, ciphertext_2, kem_id, ciphertext_kem]
    return cbor2.dumps(msg)

def parse_msg2(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {
        "g_y":            msg[0],
        "c_r":            msg[1],
        "ciphertext_2":   msg[2],
        "kem_id":         msg[3],
        "ciphertext_kem": msg[4],
    }

def build_msg3() -> bytes:
    ciphertext_3 = os.urandom(16)
    msg = [ciphertext_3]
    return cbor2.dumps(msg)

def parse_msg3(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {"ciphertext_3": msg[0]}
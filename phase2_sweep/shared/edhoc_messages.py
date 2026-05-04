import os
import cbor2

def build_msg1(supported_kems: list, g_x: bytes, observed_rtt_ms: float = 0.0) -> bytes:
    c_i = os.urandom(1)
    msg = [0, supported_kems[0], g_x, c_i, supported_kems, observed_rtt_ms]
    return cbor2.dumps(msg)

def parse_msg1(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {
        "method":          msg[0],
        "suite":           msg[1],
        "g_x":             msg[2],
        "c_i":             msg[3],
        "supported_kems":  msg[4],
        "observed_rtt_ms": float(msg[5]) if len(msg) > 5 else 0.0,
    }

def build_msg2(selected_kem: int, condition_code: str,
               g_y: bytes, ciphertext_kem: bytes) -> bytes:
    c_r          = os.urandom(1)
    ciphertext_2 = os.urandom(16)
    msg = [g_y, c_r, ciphertext_2, selected_kem, condition_code, ciphertext_kem]
    return cbor2.dumps(msg)

def parse_msg2(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {
        "g_y":            msg[0],
        "c_r":            msg[1],
        "ciphertext_2":   msg[2],
        "selected_kem":   msg[3],
        "condition_code": msg[4],
        "ciphertext_kem": msg[5],
    }

def build_msg3() -> bytes:
    return cbor2.dumps([os.urandom(16)])

def parse_msg3(data: bytes) -> dict:
    msg = cbor2.loads(data)
    return {"ciphertext_3": msg[0]}
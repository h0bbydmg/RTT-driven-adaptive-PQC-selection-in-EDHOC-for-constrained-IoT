import asyncio
import logging
import os
import time

import aiocoap

from shared.cose_kem import (
    KEMContext,
    KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768, KEM_ML_KEM_1024, KEM_NAMES
)
from shared.edhoc_messages import build_msg1, parse_msg2, build_msg3

log = logging.getLogger(__name__)

RESPONDER_HOST     = os.environ.get("RESPONDER_HOST", "localhost")
RESPONDER_URI_MSG2 = f"coap://{RESPONDER_HOST}/edhoc"
RESPONDER_URI_MSG3 = f"coap://{RESPONDER_HOST}/edhoc3"

ALL_KEMS = [KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768, KEM_ML_KEM_1024]

HANDSHAKE_TIMEOUT_S = 120.0

DEGRADED_THRESHOLD_MS = {
    KEM_ECDH_P256:   200,
    KEM_ML_KEM_512:  425,
    KEM_ML_KEM_768:  625,
    KEM_ML_KEM_1024: 830,
}


async def run_handshake(protocol, kem_id: int) -> dict:
    kem = KEMContext(kem_id)
    metrics = {
        "kem":        KEM_NAMES[kem_id],
        "success":    False,
        "degraded":   False,
        "total_ms":   None,
        "rtt_ms":     None,
        "msg1_bytes": None,
        "msg2_bytes": None,
        "error":      None,
    }

    try:
        t0 = time.perf_counter()

        pk_i, sk_i = kem.generate_keypair()

        msg1_payload = build_msg1(kem_id, pk_i)
        metrics["msg1_bytes"] = len(msg1_payload)

        request = aiocoap.Message(
            code=aiocoap.POST,
            uri=RESPONDER_URI_MSG2,
            payload=msg1_payload
        )

        t_send = time.perf_counter()
        response = await asyncio.wait_for(
            protocol.request(request).response,
            timeout=HANDSHAKE_TIMEOUT_S
        )
        t_recv = time.perf_counter()

        metrics["rtt_ms"]     = (t_recv - t_send) * 1000
        metrics["msg2_bytes"] = len(response.payload)

        msg2 = parse_msg2(response.payload)
        ct   = msg2["ciphertext_kem"]
        kem.decapsulate(sk_i, ct)

        msg3_payload = build_msg3()
        request3 = aiocoap.Message(
            code=aiocoap.POST,
            uri=RESPONDER_URI_MSG3,
            payload=msg3_payload
        )
        await asyncio.wait_for(
            protocol.request(request3).response,
            timeout=HANDSHAKE_TIMEOUT_S
        )

        t_done = time.perf_counter()
        total_ms = (t_done - t0) * 1000
        metrics["total_ms"] = total_ms
        metrics["success"]  = True

        threshold = DEGRADED_THRESHOLD_MS[kem_id]
        if total_ms > threshold:
            metrics["degraded"] = True
            log.debug(
                f"DEGRADED: {KEM_NAMES[kem_id]} took {total_ms:.0f}ms "
                f"(threshold {threshold}ms)"
            )

    except asyncio.TimeoutError:
        metrics["error"] = "TIMEOUT"
    except Exception as e:
        metrics["error"] = str(e)

    return metrics


async def run_all_kems() -> list[dict]:
    protocol = await aiocoap.Context.create_client_context()
    results = []
    for kem_id in ALL_KEMS:
        m = await run_handshake(protocol, kem_id)
        results.append(m)
        await asyncio.sleep(0.5)
    await protocol.shutdown()
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [INITIATOR] %(message)s")
    results = asyncio.run(run_all_kems())
    for r in results:
        print(r)
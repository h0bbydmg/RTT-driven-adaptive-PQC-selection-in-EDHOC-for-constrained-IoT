import asyncio
import logging
import os
import statistics
import time

import aiocoap
import cbor2

from shared.cose_kem import (
    KEMContext,
    KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768, KEM_NAMES
)
from shared.edhoc_messages import build_msg1, parse_msg2, build_msg3

log = logging.getLogger(__name__)

RESPONDER_HOST      = os.environ.get("RESPONDER_HOST", "localhost")
RESPONDER_URI_MSG2  = f"coap://{RESPONDER_HOST}/edhoc"
RESPONDER_URI_MSG3  = f"coap://{RESPONDER_HOST}/edhoc3"
RESPONDER_URI_PROBE = f"coap://{RESPONDER_HOST}/probe"

HANDSHAKE_TIMEOUT_S = 120.0

SUPPORTED_KEMS = [KEM_ML_KEM_768, KEM_ML_KEM_512, KEM_ECDH_P256]

KEM_BASE_MS = {
    KEM_ECDH_P256:   40,
    KEM_ML_KEM_512:  50,
    KEM_ML_KEM_768:  100,
}

RTT_FACTOR = 10

PROBE_COUNT     = 5
PROBE_TIMEOUT_S = 15.0


async def measure_rtt(protocol) -> float:
    rtts = []
    for _ in range(PROBE_COUNT):
        try:
            req = aiocoap.Message(code=aiocoap.GET, uri=RESPONDER_URI_PROBE)
            t_p = time.perf_counter()
            await asyncio.wait_for(
                protocol.request(req).response,
                timeout=PROBE_TIMEOUT_S,
            )
            rtts.append((time.perf_counter() - t_p) * 1000)
        except Exception:
            pass
        await asyncio.sleep(0.1)

    if not rtts:
        log.warning("All RTT probes failed — sending 0.0 (responder will use fallback)")
        return 0.0

    median_rtt = statistics.median(rtts)
    log.debug(
        f"RTT probes: {[f'{r:.1f}' for r in rtts]} ms "
        f"→ median={median_rtt:.1f}ms ({len(rtts)}/{PROBE_COUNT} succeeded)"
    )
    return median_rtt


def compute_degraded_threshold(kem_id: int, probe_rtt_ms: float) -> float:
    base = KEM_BASE_MS.get(kem_id, 100)
    return base + probe_rtt_ms * RTT_FACTOR


async def run_handshake(protocol) -> dict:
    metrics = {
        "success":        False,
        "degraded":       False,
        "selected_kem":   None,
        "condition_code": None,
        "probe_rtt_ms":   None,
        "total_ms":       None,
        "rtt_ms":         None,
        "msg1_bytes":     None,
        "msg2_bytes":     None,
        "error":          None,
    }

    try:
        probe_rtt = await measure_rtt(protocol)
        metrics["probe_rtt_ms"] = probe_rtt

        t0 = time.perf_counter()

        keypairs = {}
        pk_map   = {}
        for kem_id in SUPPORTED_KEMS:
            kem = KEMContext(kem_id)
            pk, dk = kem.generate_keypair()
            keypairs[kem_id] = (pk, dk)
            pk_map[kem_id]   = pk

        g_x = cbor2.dumps(pk_map)

        msg1_payload = build_msg1(SUPPORTED_KEMS, g_x, observed_rtt_ms=probe_rtt)
        metrics["msg1_bytes"] = len(msg1_payload)

        request = aiocoap.Message(
            code=aiocoap.POST,
            uri=RESPONDER_URI_MSG2,
            payload=msg1_payload,
        )

        t_send   = time.perf_counter()
        response = await asyncio.wait_for(
            protocol.request(request).response,
            timeout=HANDSHAKE_TIMEOUT_S,
        )
        t_recv = time.perf_counter()

        metrics["rtt_ms"]     = (t_recv - t_send) * 1000
        metrics["msg2_bytes"] = len(response.payload)

        msg2            = parse_msg2(response.payload)
        selected_kem_id = msg2["selected_kem"]
        condition_code  = msg2["condition_code"]
        ct              = msg2["ciphertext_kem"]

        metrics["selected_kem"]   = KEM_NAMES[selected_kem_id]
        metrics["condition_code"] = condition_code

        if selected_kem_id not in keypairs:
            raise ValueError(
                f"Responder selected {KEM_NAMES[selected_kem_id]} "
                f"but initiator has no keypair for it"
            )

        kem = KEMContext(selected_kem_id)
        _, dk = keypairs[selected_kem_id]
        kem.decapsulate(dk, ct)

        request3 = aiocoap.Message(
            code=aiocoap.POST,
            uri=RESPONDER_URI_MSG3,
            payload=build_msg3(),
        )
        await asyncio.wait_for(
            protocol.request(request3).response,
            timeout=HANDSHAKE_TIMEOUT_S,
        )

        t_done   = time.perf_counter()
        total_ms = (t_done - t0) * 1000

        metrics["total_ms"] = total_ms
        metrics["success"]  = True

        threshold = compute_degraded_threshold(selected_kem_id, probe_rtt)
        if total_ms > threshold:
            metrics["degraded"] = True

    except asyncio.TimeoutError:
        metrics["error"] = "TIMEOUT"
    except Exception as e:
        metrics["error"] = str(e)

    return metrics


async def run_single() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [INITIATOR] %(message)s")
    protocol = await aiocoap.Context.create_client_context()
    m = await run_handshake(protocol)
    await protocol.shutdown()
    print(m)


if __name__ == "__main__":
    asyncio.run(run_single())
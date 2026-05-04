import asyncio
import logging
import os
import time

import aiocoap
import aiocoap.resource as resource
import cbor2

from shared.cose_kem import (
    KEMContext,
    KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768, KEM_NAMES
)
from shared.edhoc_messages import parse_msg1, build_msg2, parse_msg3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RESPONDER] %(message)s"
)
log = logging.getLogger(__name__)

COAP_MAX_DATAGRAM = 1024

def select_kem(supported_kems: list, rtt_ms: float) -> tuple:
    if rtt_ms < 50:
        preferred, condition = KEM_ML_KEM_768, "GOOD"
    elif rtt_ms <= 120:
        preferred, condition = KEM_ML_KEM_512, "MEDIUM"
    else:
        preferred, condition = KEM_ECDH_P256,  "POOR"

    if preferred in supported_kems:
        return preferred, condition

    for fallback in [KEM_ML_KEM_512, KEM_ECDH_P256]:
        if fallback in supported_kems:
            log.warning(
                f"Preferred {KEM_NAMES[preferred]} not advertised, "
                f"falling back to {KEM_NAMES[fallback]}"
            )
            return fallback, condition + "_FALLBACK"

    last = supported_kems[0]
    return last, condition + "_LAST_RESORT"


def estimate_rtt_from_retransmits(request) -> float:
    rc = getattr(request, "retransmit_count", 0) or 0
    return {0: 20.0, 1: 80.0}.get(rc, 200.0)


# ── CoAP Resources ────────────────────────────────────────────────────────────

class ProbeResource(resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"")


class EDHOCResource(resource.Resource):
    def __init__(self):
        super().__init__()
        self.sessions = {}

    async def render_post(self, request):
        t_arrival = time.perf_counter()

        msg1           = parse_msg1(request.payload)
        supported_kems = msg1["supported_kems"]
        g_x_raw        = msg1["g_x"]
        c_i_hex        = msg1["c_i"].hex()
        observed_rtt   = msg1["observed_rtt_ms"]

        exceeds_mtu = len(request.payload) > COAP_MAX_DATAGRAM

        if observed_rtt > 0.0:
            rtt_for_policy = observed_rtt
            rtt_source     = "initiator-probe"
        else:
            rtt_for_policy = estimate_rtt_from_retransmits(request)
            rtt_source     = "retransmit-estimate"

        log.info(
            f"MSG1 | supported={[KEM_NAMES[k] for k in supported_kems]} "
            f"| payload={len(request.payload)}B"
            f"{' BLOCKWISE' if exceeds_mtu else ''} "
            f"| RTT={rtt_for_policy:.1f}ms [{rtt_source}]"
        )

        selected_kem_id, condition_code = select_kem(supported_kems, rtt_for_policy)
        log.info(
            f"Selected: {KEM_NAMES[selected_kem_id]} [{condition_code}] "
            f"(RTT={rtt_for_policy:.1f}ms)"
        )

        try:
            pk_map = cbor2.loads(g_x_raw)
        except Exception:
            pk_map = {supported_kems[0]: g_x_raw}

        if selected_kem_id not in pk_map:
            log.error(f"No pk for {KEM_NAMES[selected_kem_id]}, using first available")
            selected_kem_id = list(pk_map.keys())[0]

        initiator_pk = pk_map[selected_kem_id]

        kem = KEMContext(selected_kem_id)
        ct, ss = kem.encapsulate(initiator_pk)
        pk_r, _ = kem.generate_keypair()

        log.info(f"Encapsulate | ct={len(ct)}B | SS={ss[:8].hex()}…")

        self.sessions[c_i_hex] = {
            "selected_kem":   selected_kem_id,
            "condition_code": condition_code,
            "ss":             ss,
            "t_start":        t_arrival,
        }

        msg2_payload = build_msg2(selected_kem_id, condition_code, pk_r, ct)
        log.info(f"MSG2 | payload={len(msg2_payload)}B")

        return aiocoap.Message(code=aiocoap.CHANGED, payload=msg2_payload)


class EDHOCMSG3Resource(resource.Resource):
    def __init__(self, session_store: dict):
        super().__init__()
        self.sessions = session_store

    async def render_post(self, request):
        t_done = time.perf_counter()
        parse_msg3(request.payload)

        if self.sessions:
            c_i  = list(self.sessions.keys())[-1]
            sess = self.sessions.pop(c_i)
            ms   = (t_done - sess["t_start"]) * 1000
            log.info(
                f"MSG3 | KEM={KEM_NAMES[sess['selected_kem']]} "
                f"| condition={sess['condition_code']} "
                f"| handshake={ms:.2f}ms "
                f"| sessions_remaining={len(self.sessions)}"
            )
        else:
            log.warning("MSG3 received but no active session")

        return aiocoap.Message(code=aiocoap.CHANGED, payload=b"OK")

async def main():
    root      = resource.Site()
    edhoc_res = EDHOCResource()

    root.add_resource(["probe"],  ProbeResource())
    root.add_resource(["edhoc"],  edhoc_res)
    root.add_resource(["edhoc3"], EDHOCMSG3Resource(edhoc_res.sessions))

    await aiocoap.Context.create_server_context(root, bind=("0.0.0.0", 5683))
    log.info("EDHOC Phase 2 Agile Responder listening on CoAP udp://0.0.0.0:5683")
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
import asyncio
import logging
import os
import time

import aiocoap
import aiocoap.resource as resource

from shared.cose_kem import (
    KEMContext,
    KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768, KEM_ML_KEM_1024, KEM_NAMES
)
from shared.edhoc_messages import parse_msg1, build_msg2, parse_msg3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RESPONDER] %(message)s"
)
log = logging.getLogger(__name__)

COAP_MAX_DATAGRAM = 1024

class EDHOCResource(resource.Resource):

    def __init__(self):
        super().__init__()
        self.sessions = {}

    async def render_post(self, request):
        payload = request.payload
        msg1    = parse_msg1(payload)
        kem_id  = msg1["kem_id"]
        g_x     = msg1["g_x"]
        c_i     = msg1["c_i"].hex()

        kem = KEMContext(kem_id)
        exceeds_datagram = len(payload) > COAP_MAX_DATAGRAM

        log.info(
            f"MSG1 | KEM={KEM_NAMES[kem_id]} | pk_size={len(g_x)}B "
            f"| payload={len(payload)}B"
            f"{' | BLOCKWISE' if exceeds_datagram else ''}"
        )

        t_start = time.perf_counter()
        ct, ss  = kem.encapsulate(g_x)
        t_kem   = (time.perf_counter() - t_start) * 1000

        log.info(
            f"Encapsulate | SS={ss[:8].hex()}… | ct_size={len(ct)}B "
            f"| t={t_kem:.2f}ms"
        )

        pk_r, _ = kem.generate_keypair()

        self.sessions[c_i] = {
            "kem_id":  kem_id,
            "ss":      ss,
            "t_start": t_start,
        }

        msg2_payload = build_msg2(kem_id, pk_r, ct)
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
            c_i = list(self.sessions.keys())[-1]
            sess = self.sessions.pop(c_i)
            duration_ms = (t_done - sess["t_start"]) * 1000
            log.info(
                f"MSG3 | KEM={KEM_NAMES[sess['kem_id']]} "
                f"| handshake={duration_ms:.2f}ms | sessions_remaining={len(self.sessions)}"
            )
        else:
            log.warning("MSG3 received but no session found")

        return aiocoap.Message(code=aiocoap.CHANGED, payload=b"OK")


async def main():
    root        = resource.Site()
    edhoc_res   = EDHOCResource()
    root.add_resource(["edhoc"],  edhoc_res)
    root.add_resource(["edhoc3"], EDHOCMSG3Resource(edhoc_res.sessions))

    await aiocoap.Context.create_server_context(root, bind=("0.0.0.0", 5683))
    log.info("EDHOC Responder listening on CoAP udp://0.0.0.0:5683")
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
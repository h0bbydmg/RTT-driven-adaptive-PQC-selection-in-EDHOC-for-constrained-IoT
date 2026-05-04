import asyncio
import csv
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, "/app")

import aiocoap.numbers.constants as _coap_const
_coap_const.ACK_TIMEOUT        = 30.0
_coap_const.ACK_MAX_RETRANSMIT = 8
_coap_const.MAX_TRANSMIT_WAIT  = 930.0

from initiator.initiator import run_handshake, ALL_KEMS, DEGRADED_THRESHOLD_MS
from shared.cose_kem import KEM_NAMES
import aiocoap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SWEEP] %(message)s"
)
log = logging.getLogger(__name__)

LOSS_LEVELS        = [0, 5, 10, 20, 30]
LATENCY_LEVELS     = [10, 50, 100, 150]
RUNS_PER_CONDITION = 5
NETWORK_IFACE      = "eth0"
OUTPUT_DIR         = "/app/results"
OUTPUT_FILE        = f"{OUTPUT_DIR}/sweep_phase1_v3.csv"

CSV_FIELDS = [
    "loss_pct", "latency_ms", "kem", "run",
    "success", "degraded", "total_ms", "rtt_ms",
    "msg1_bytes", "msg2_bytes", "error",
]

def _run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        log.warning(f"cmd: {cmd} → {r.stderr.strip()}")
    return r

def apply_netem(loss_pct, latency_ms):
    _run(f"tc qdisc del dev {NETWORK_IFACE} root", check=False)
    loss_arg = f"loss {loss_pct}% 25%" if loss_pct > 0 else ""
    cmd = f"tc qdisc add dev {NETWORK_IFACE} root netem delay {latency_ms}ms 5ms {loss_arg}".strip()
    _run(cmd)
    log.info(f"netem: loss={loss_pct}% latency={latency_ms}ms")

def clear_netem():
    _run(f"tc qdisc del dev {NETWORK_IFACE} root", check=False)

async def run_condition(protocol, loss_pct, latency_ms, writer, f):
    log.info(f"{'='*60}")
    log.info(f"Condition: loss={loss_pct}%  latency={latency_ms}ms")
    log.info(f"{'='*60}")

    for kem_id in ALL_KEMS:
        kem_name  = KEM_NAMES[kem_id]
        successes = 0
        degraded  = 0

        for run_i in range(1, RUNS_PER_CONDITION + 1):
            metrics = await run_handshake(protocol, kem_id)

            is_degraded = metrics["degraded"]
            row = {
                "loss_pct":   loss_pct,
                "latency_ms": latency_ms,
                "kem":        kem_name,
                "run":        run_i,
                "success":    metrics["success"],
                "degraded":   is_degraded,
                "total_ms":   round(metrics["total_ms"], 2) if metrics["total_ms"] else "",
                "rtt_ms":     round(metrics["rtt_ms"],   2) if metrics["rtt_ms"]   else "",
                "msg1_bytes": metrics["msg1_bytes"] or "",
                "msg2_bytes": metrics["msg2_bytes"] or "",
                "error":      metrics["error"] or "",
            }
            writer.writerow(row)
            f.flush()

            tag = ""
            if not metrics["success"]:
                tag = f"✗ ({metrics['error']})"
            elif is_degraded:
                tag = f"~ DEGRADED ({metrics['total_ms']:.0f}ms)"
                degraded += 1
            else:
                tag = f"✓ ({metrics['total_ms']:.0f}ms)"
                successes += 1

            log.info(f"  [{kem_name}] run {run_i}: {tag}")
            await asyncio.sleep(1.5)

        clean     = successes
        deg       = degraded
        failed    = RUNS_PER_CONDITION - successes - degraded
        log.info(
            f"  → {kem_name}: clean={clean} degraded={deg} failed={failed} "
            f"/ {RUNS_PER_CONDITION}"
        )


async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total = len(LOSS_LEVELS) * len(LATENCY_LEVELS) * len(ALL_KEMS) * RUNS_PER_CONDITION
    log.info(f"Phase 1 Sweep v3 | {total} handshakes")
    log.info(f"Degraded thresholds: "
             + ", ".join(f"{KEM_NAMES[k]}>{v}ms" for k,v in DEGRADED_THRESHOLD_MS.items()))

    await asyncio.sleep(5)

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        f.flush()

        protocol = await aiocoap.Context.create_client_context()

        try:
            for latency_ms in LATENCY_LEVELS:
                for loss_pct in LOSS_LEVELS:
                    apply_netem(loss_pct, latency_ms)
                    await asyncio.sleep(3)
                    await run_condition(protocol, loss_pct, latency_ms, writer, f)
                    clear_netem()
                    await asyncio.sleep(2)
        finally:
            clear_netem()
            await protocol.shutdown()

    log.info("=" * 60)
    log.info("SWEEP COMPLETE — degraded success summary")
    log.info(f"{'KEM':<14} {'Loss':>5} {'Lat':>4}  {'Clean':>5} {'Degraded':>8} {'Failed':>6}")
    log.info("-" * 60)

    import csv as _csv
    with open(OUTPUT_FILE) as f:
        rows = list(_csv.DictReader(f))

    for kem_name in [KEM_NAMES[k] for k in ALL_KEMS]:
        for lat in LATENCY_LEVELS:
            for loss in LOSS_LEVELS:
                subset = [r for r in rows
                          if r["kem"]==kem_name
                          and int(r["latency_ms"])==lat
                          and int(r["loss_pct"])==loss]
                if not subset:
                    continue
                clean    = sum(1 for r in subset if r["success"]=="True" and r["degraded"]=="False")
                deg      = sum(1 for r in subset if r["success"]=="True" and r["degraded"]=="True")
                failed   = sum(1 for r in subset if r["success"]=="False")
                if deg > 0 or failed > 0:
                    log.info(f"{kem_name:<14} {loss:>4}% {lat:>3}ms  {clean:>5} {deg:>8} {failed:>6}")

    log.info("=" * 60)
    log.info(f"Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
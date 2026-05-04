import asyncio
import csv
import logging
import os
import subprocess
import sys

sys.path.insert(0, "/app")

import aiocoap.numbers.constants as _coap_const
_coap_const.ACK_TIMEOUT        = 30.0
_coap_const.ACK_MAX_RETRANSMIT = 8
_coap_const.MAX_TRANSMIT_WAIT  = 930.0

from shared.cose_kem import KEM_NAMES, KEM_ECDH_P256, KEM_ML_KEM_512, KEM_ML_KEM_768
import aiocoap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SWEEP-P2] %(message)s"
)
log = logging.getLogger(__name__)

LOSS_LEVELS        = [0, 5, 10, 20, 30]
LATENCY_LEVELS     = [10, 50, 100, 150]
RUNS_PER_CONDITION = 5
NETWORK_IFACE      = "eth0"
OUTPUT_DIR         = "/app/results"
OUTPUT_FILE        = f"{OUTPUT_DIR}/sweep_phase2.csv"

SUPPORTED_KEMS = [KEM_ML_KEM_768, KEM_ML_KEM_512, KEM_ECDH_P256]

CSV_FIELDS = [
    "loss_pct", "latency_ms", "run",
    "success", "degraded",
    "selected_kem", "condition_code",
    "probe_rtt_ms",
    "total_ms", "rtt_ms",
    "msg1_bytes", "msg2_bytes",
    "error",
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
    from initiator.initiator import run_handshake

    log.info("=" * 60)
    log.info(f"Condition: loss={loss_pct}%  latency={latency_ms}ms")
    log.info("=" * 60)

    rows   = []
    counts = {"clean": 0, "degraded": 0, "failed": 0}

    for run_i in range(1, RUNS_PER_CONDITION + 1):
        log.info(f"  Run {run_i}/{RUNS_PER_CONDITION}")
        metrics = await run_handshake(protocol)

        row = {
            "loss_pct":       loss_pct,
            "latency_ms":     latency_ms,
            "run":            run_i,
            "success":        metrics["success"],
            "degraded":       metrics["degraded"],
            "selected_kem":   metrics["selected_kem"]   or "",
            "condition_code": metrics["condition_code"] or "",
            "probe_rtt_ms":   metrics["probe_rtt_ms"]   or "",
            "total_ms":       round(metrics["total_ms"], 2) if metrics["total_ms"] else "",
            "rtt_ms":         round(metrics["rtt_ms"],   2) if metrics["rtt_ms"]   else "",
            "msg1_bytes":     metrics["msg1_bytes"] or "",
            "msg2_bytes":     metrics["msg2_bytes"] or "",
            "error":          metrics["error"] or "",
        }
        writer.writerow(row)
        f.flush()
        rows.append(row)

        kem  = metrics["selected_kem"]   or "?"
        cond = metrics["condition_code"] or "?"
        prtt = metrics["probe_rtt_ms"]   or 0

        if not metrics["success"]:
            log.info(f"    ✗ ({metrics['error']})")
            counts["failed"] += 1
        elif metrics["degraded"]:
            log.info(f"    ~ DEGRADED | {kem} [{cond}] | probe_rtt={prtt:.1f}ms | {metrics['total_ms']:.0f}ms")
            counts["degraded"] += 1
        else:
            log.info(f"    ✓ | {kem} [{cond}] | probe_rtt={prtt:.1f}ms | {metrics['total_ms']:.0f}ms")
            counts["clean"] += 1

        await asyncio.sleep(1.5)

    log.info(
        f"  → clean={counts['clean']} degraded={counts['degraded']} "
        f"failed={counts['failed']} / {RUNS_PER_CONDITION}"
    )
    return rows


async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total = len(LOSS_LEVELS) * len(LATENCY_LEVELS) * RUNS_PER_CONDITION
    log.info(f"Phase 2 Sweep v4 | {total} handshakes")
    log.info(f"Advertised KEMs: {[KEM_NAMES[k] for k in SUPPORTED_KEMS]}")

    await asyncio.sleep(5)

    all_rows = []

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

                    rows = await run_condition(
                        protocol, loss_pct, latency_ms, writer, f
                    )
                    all_rows.extend(rows)
                    clear_netem()
                    await asyncio.sleep(2)
        finally:
            clear_netem()
            await protocol.shutdown()

    log.info("=" * 60)
    log.info("SWEEP COMPLETE — KEM selection distribution")
    log.info(f"{'Loss':>5} {'Lat':>5}  {'GOOD/768':>9} {'MED/512':>8} {'POOR/P256':>10} {'Degraded':>9} {'Failed':>7}")
    log.info("-" * 60)

    for latency_ms in LATENCY_LEVELS:
        for loss_pct in LOSS_LEVELS:
            subset = [r for r in all_rows
                      if r["loss_pct"] == loss_pct and r["latency_ms"] == latency_ms]
            if not subset:
                continue
            good     = sum(1 for r in subset if r["success"] and "GOOD"   in str(r["condition_code"]))
            medium   = sum(1 for r in subset if r["success"] and "MEDIUM" in str(r["condition_code"]))
            poor     = sum(1 for r in subset if r["success"] and "POOR"   in str(r["condition_code"]))
            degraded = sum(1 for r in subset if r["success"] and r["degraded"])
            failed   = sum(1 for r in subset if not r["success"])
            log.info(
                f"{loss_pct:>4}% {latency_ms:>4}ms  "
                f"{good:>9} {medium:>8} {poor:>10} {degraded:>9} {failed:>7}"
            )

    log.info("=" * 60)
    log.info(f"Results → {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
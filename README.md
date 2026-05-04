# RTT-Driven Adaptive Post-Quantum KEM Selection in EDHOC over CoAP/UDP for Constrained IoT

This project implements and evaluates a two-phase solution:
- **Phase 1** - Static PQC integration: embeds ML-KEM-512, ML-KEM-768, and ML-KEM-1024 into EDHOC over CoAP/UDP and characterises their performance across 400 handshakes under a full network impairment matrix.
- **Phase 2** - Agile PQC selection: the initiator measures RTT via a pre-handshake multi-probe CoAP ping, embeds the result in MSG1, and the responder automatically selects the most secure KEM the network can reliably support. Achieves **100% completion** across all 100 tested handshakes while retaining quantum-resistant KEMs in **74%** of them.

---
## Repository Structure

```
├── phase1_sweep/
│   ├── initiator/          # Phase 1 handshake initiator
│   ├── responder/          # Phase 1 CoAP responder (/edhoc, /edhoc3)
│   ├── shared/             # KEM abstraction layer + CBOR message builders
│   ├── sweep.py            # Sweep orchestrator (network condition matrix)
│   ├── docker-compose.yml
│   └── results/            # CSV output (400 handshakes)
│
└── phase2_sweep/
    ├── initiator/          # Phase 2 initiator with RTT probe + multi-key MSG1
    ├── responder/          # Phase 2 responder with KEM selection policy
    ├── shared/             # Shared KEM abstraction + CBOR message builders
    ├── sweep.py            # Sweep orchestrator with probe-based RTT measurement
    ├── docker-compose.yml
    └── results/            # CSV output (100 handshakes)
```

---
## Getting Started

**Requirements:** Docker, Docker Compose

```bash
# Clone the repo
git clone https://github.com/h0bbydmg/RTT-driven-adaptive-PQC-selection-in-EDHOC-for-constrained-IoT.git
cd RTT-driven-adaptive-PQC-selection-in-EDHOC-for-constrained-IoT

# Run Phase 1 sweep
cd phase1_sweep
docker compose up --build

# Run Phase 2 sweep
cd ../phase2_sweep
docker compose up --build
```

Results are written to `results/sweep_phase1.csv` and `results/sweep_phase2.csv` respectively, with one row per handshake including: loss level, latency, KEM used, success/degraded/failed classification, total_ms, rtt_ms, msg sizes, and (Phase 2 only) probe_rtt_ms, selected_kem, and condition_code.

---
## Dependencies

| Package      | Version | Purpose                            |
| ------------ | ------- | ---------------------------------- |
| Python       | 3.11    | Runtime                            |
| aiocoap      | 0.4.7   | Async CoAP with blockwise transfer |
| cbor2        | 5.4.6   | CBOR encoding/decoding             |
| cryptography | ≥41.0   | ECDH-P256 operations               |
| kyber-py     | latest  | NIST FIPS 203 ML-KEM               |
| iproute2     | system  | tc netem network emulation         |

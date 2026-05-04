from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, NoEncryption, PrivateFormat
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

KEM_ECDH_P256   = -25
KEM_ML_KEM_512  = -0x200
KEM_ML_KEM_768  = -0x201
KEM_ML_KEM_1024 = -0x202

KEM_NAMES = {
    KEM_ECDH_P256:   "ECDH-P256",
    KEM_ML_KEM_512:  "ML-KEM-512",
    KEM_ML_KEM_768:  "ML-KEM-768",
    KEM_ML_KEM_1024: "ML-KEM-1024",
}

MLKEM_MODULES = {
    KEM_ML_KEM_512:  ML_KEM_512,
    KEM_ML_KEM_768:  ML_KEM_768,
    KEM_ML_KEM_1024: ML_KEM_1024,
}


class KEMContext:
    def __init__(self, kem_id: int):
        if kem_id not in KEM_NAMES:
            raise ValueError(f"Unknown KEM id: {kem_id}")
        self.kem_id = kem_id
        self.name = KEM_NAMES[kem_id]

    def generate_keypair(self):
        if self.kem_id == KEM_ECDH_P256:
            priv = generate_private_key(SECP256R1(), default_backend())
            pub_bytes = priv.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            priv_bytes = priv.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            return pub_bytes, priv_bytes
        else:
            mlkem = MLKEM_MODULES[self.kem_id]
            ek, dk = mlkem.keygen()
            return ek, dk

    def encapsulate(self, public_key_bytes: bytes):
        if self.kem_id == KEM_ECDH_P256:
            eph_priv = generate_private_key(SECP256R1(), default_backend())
            eph_pub_bytes = eph_priv.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            resp_pub = EllipticCurvePublicKey.from_encoded_point(
                SECP256R1(), public_key_bytes
            )
            shared_secret = eph_priv.exchange(ECDH(), resp_pub)
            return eph_pub_bytes, shared_secret
        else:
            mlkem = MLKEM_MODULES[self.kem_id]
            ss, ct = mlkem.encaps(public_key_bytes)
            return ct, ss

    def decapsulate(self, secret_key_bytes: bytes, ciphertext_bytes: bytes):
        if self.kem_id == KEM_ECDH_P256:
            priv = load_pem_private_key(secret_key_bytes, password=None)
            eph_pub = EllipticCurvePublicKey.from_encoded_point(
                SECP256R1(), ciphertext_bytes
            )
            return priv.exchange(ECDH(), eph_pub)
        else:
            mlkem = MLKEM_MODULES[self.kem_id]
            ss = mlkem.decaps(secret_key_bytes, ciphertext_bytes)
            return ss

    def public_key_size(self) -> str:
        sizes = {
            KEM_ECDH_P256:   "65 bytes (uncompressed P256)",
            KEM_ML_KEM_512:  "800 bytes",
            KEM_ML_KEM_768:  "1184 bytes",
            KEM_ML_KEM_1024: "1568 bytes",
        }
        return sizes[self.kem_id]
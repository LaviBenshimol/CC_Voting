"""
interactive_paillier_zkp.py
───────────────────────────
Interactive Σ-protocol that proves a Paillier ciphertext encrypts **either 0 or 1**,
augmented with a hash-commitment so the prover cannot switch the vote mid-protocol.

Flow (client = Verifier, server = Prover):

    prover  = Prover(pubkey, vote_bit)
    commitment = prover.commit()            # ➊ send to client

    verifier = Verifier(pubkey, commitment) # ➋ store commitment

    A0, A1 = prover.prove_step1()           # ➌ first ZKP message
    c      = verifier.verify_step1()        # ➍ random challenge
    proof  = prover.prove_step2(c)          # ➎ response  (+ salt reveal)
    ok     = verifier.verify_step2(proof)   # ➏ final check
"""
from __future__ import annotations
import hashlib, math, secrets
import random
from random import SystemRandom
from phe import paillier
from dataclasses import dataclass

@dataclass
class ZKPStep1Msg:          # → /zkp/step1
    voter_id: str
    commitment: str         # hex
    C: str                  # int in decimal
    A0: str
    A1: str

@dataclass
class ZKPStep2Msg:          # → /zkp/step2
    voter_id: str
    e0: str; e1: str; z0: str; z1: str
    salt: str
# ───────────────────────────── constants ────────────────────────────────
KEY_BITS       = 2048
CHALLENGE_BITS = 128
sysrand        = SystemRandom()

# ──────────────────────────── small helpers ─────────────────────────────
def random_coprime(n: int) -> int:
    while True:
        r = secrets.randbelow(n)
        if 1 < r < n and math.gcd(r, n) == 1:
            return r

MOD_MASK = (1 << CHALLENGE_BITS) - 1           # handy 2^t – 1

def commit(secret: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    h = hashlib.sha256((secret + salt).encode()).hexdigest()
    return h, salt

def verify_commit(secret: str, salt: str, h: str) -> bool:
    return h == hashlib.sha256((secret + salt).encode()).hexdigest()

# ─────────────────────────── OR-proof building blocks ───────────────────
def _branch_values(pk, C: int, vote_bit: int,
                   s_real: int, e_sim: int, z_sim: int) -> tuple[int, int]:
    """
    Return the commitment pair (A0, A1).
    Only the simulated branch depends on e_sim / z_sim.
    """
    n, n2, g = pk.n, pk.n ** 2, pk.n + 1

    if vote_bit == 0:
        A0 = pow(s_real, n, n2)  # real

        # Correctly calculate the base for the simulated proof first
        C_prime = (C * pow(g, -1, n2)) % n2
        sim_base1 = pow(C_prime, e_sim, n2)
        A1 = (pow(z_sim, n, n2) * pow(sim_base1, -1, n2)) % n2  # sim
    else:  # vote_bit == 1
        A1 = pow(s_real, n, n2)  # real

        # The base for this simulated proof is simply C
        sim_base0 = pow(C, e_sim, n2)
        A0 = (pow(z_sim, n, n2) * pow(sim_base0, -1, n2)) % n2  # sim

    return A0, A1


def _verify_or(pk, C: int, A0: int, A1: int,
               e0: int, e1: int, z0: int, z1: int) -> bool:
    n, n2, g = pk.n, pk.n ** 2, pk.n + 1

    # This check is correct
    ok0 = pow(z0, n, n2) == (A0 * pow(C, e0, n2)) % n2

    # Correct the base for the exponentiation in the ok1 check
    C_prime = (C * pow(g, -1, n2)) % n2
    ok1 = pow(z1, n, n2) == (A1 * pow(C_prime, e1, n2)) % n2

    return ok0 and ok1

def secret_knowledge(pubkey, vote_bit):
    """
    Encrypt `vote_bit` ∈ {0,1} with fresh randomness r and return (C, r).
    Uses same arithmetic as the sanity-check demo.
    """
    if vote_bit not in (0, 1):
        raise ValueError("vote must be 0 or 1")
    r = random_coprime(pubkey.n)
    C = paillier_encrypt_bit(pubkey.n, vote_bit, r)
    return C, r


# ──────────────────────────────  classes  ───────────────────────────────
class Prover:
    """
    Runs on the *server* holding the ballot.
    Sequence:
        commit()     → commitment string
        prove_step1()→ (C , A0 , A1)
        prove_step2(c)→ proof dict
    """
    def __init__(self, pk, vote_bit):
        if vote_bit not in (0, 1):
            raise ValueError("vote_bit must be 0 or 1")
        self.pk        = pk
        self.vote_bit  = vote_bit
        self.C, self.r = secret_knowledge(pk, vote_bit)
        self.s_real    = random_coprime(pk.n)
        self.e_sim     = sysrand.getrandbits(CHALLENGE_BITS)
        self.z_sim     = random_coprime(pk.n)
        self.A0, self.A1 = _branch_values(
            pk, self.C, vote_bit, self.s_real,
            self.e_sim, self.z_sim)

        self.commitment, self._salt = commit(str(vote_bit))

    # ➊ commitment
    def commit(self) -> str:
        return self.commitment

    # ➌ first Σ-protocol message
    def prove_step1(self):
        return self.C, self.A0, self.A1

    # ➎ response
    def prove_step2(self, challenge: int) -> dict:
        e_real = (challenge - self.e_sim) & MOD_MASK
        if self.vote_bit == 0:
            e0, e1 = e_real, self.e_sim
            z0 = (self.s_real * pow(self.r, e0, self.pk.n)) % self.pk.n
            z1 = self.z_sim
        else:
            e0, e1 = self.e_sim, e_real
            z0 = self.z_sim
            z1 = (self.s_real * pow(self.r, e1, self.pk.n)) % self.pk.n

        return dict(A0=self.A0, A1=self.A1,
                    e0=e0, e1=e1, z0=z0, z1=z1,
                    salt=self._salt)

class Verifier:
    """
    Client side.
        verify_step1()     → random challenge c
        verify_step2(C, P) → bool
    """
    def __init__(self, pk: paillier.PaillierPublicKey, commitment: str):
        self.pk = pk
        self.commitment = commitment
        self.c = None

    # ➍ challenge
    def verify_step1(self):
        self.c = sysrand.getrandbits(CHALLENGE_BITS)
        return self.c

    # ➏ final check
    def verify_step2(self, C: int, proof: dict) -> bool:
        salt = proof.pop("salt", None)
        if salt is None:
            return False

        bit = next((b for b in (0, 1)
                    if verify_commit(str(b), salt, self.commitment)), None)
        if bit is None:                 # commitment mismatch
            return False

        ok_chal = ((proof["e0"] + proof["e1"]) & MOD_MASK) == self.c
        ok_eqs  = _verify_or(self.pk, C, **proof)
        return ok_chal and ok_eqs

def paillier_encrypt_bit(n: int, bit: int, r: int) -> int:
    """
    Deterministic Paillier encryption for a single bit using g = n + 1.
    Returns the ciphertext (mod n²).
    """
    n2 = n * n
    g  = n + 1
    return (pow(g, bit, n2) * pow(r, n, n2)) % n2
# ───────────────────────────── demo & tests ─────────────────────────────
def _demo():
    print("Generating Paillier keypair …")
    pk, _ = paillier.generate_paillier_keypair(n_length=KEY_BITS)

    for bit in (0, 1):
        print(f"\n🗳️  Demo vote={bit}")
        prover   = Prover(pk, bit)
        verifier = Verifier(pk, prover.commit())

        C, A0, A1      = prover.prove_step1()
        c              = verifier.verify_step1()
        proof          = prover.prove_step2(c)

        accepted = verifier.verify_step2(C, proof)
        print("✅  Accepted" if accepted else "❌  Rejected")

    # negative test
    print("\n🔒  Commitment-mismatch test")
    bad_ver = Verifier(pk, "deadbeef")
    pr      = Prover(pk, 0)
    C, A0, A1 = pr.prove_step1()
    c_bad      = bad_ver.verify_step1()
    bad_proof  = pr.prove_step2(c_bad)
    assert not bad_ver.verify_step2(C, bad_proof)
    print("✔️  Commitment mismatch correctly rejected")

# paillier_zkp.py  (new code you’ll add)

def generate_paillier_bit_proof(pk, C_enc: paillier.EncryptedNumber,
                                plaintext_bit: int, r: int) -> dict:
    """
    Fiat–Shamir, non-interactive wrapper around Prover.
    Returns a dict that can be JSON-serialised and sent to the server.
    """
    prover = Prover(pk, plaintext_bit)          # from your tested file
    # Overwrite with caller-supplied (C,r) so the commitment matches
    prover.C, prover.r = C_enc.ciphertext(), r


    prover.A0, prover.A1 = _branch_values(pk, prover.C, plaintext_bit,
                                          prover.s_real,
                                          prover.e_sim, prover.z_sim)
    # --- Fiat-Shamir challenge ---
    transcript = f"{pk.n}{prover.C}{prover.A0}{prover.A1}"
    challenge = int(hashlib.sha256(transcript.encode()).hexdigest(), 16) & MOD_MASK
    proof = prover.prove_step2(challenge)
    proof["commitment"] = prover.commitment
    proof["salt"] = prover._salt
    proof["C"] = str(prover.C)      # send C once for completeness
    return proof


def verify_paillier_bit_proof_complete(pk, enc: paillier.EncryptedNumber,
                                       proof: dict) -> bool:
    """
    Verifier for the single-message proof produced above.
    Rejects any ciphertext not encrypting 0 or 1.
    """
    # Pull fields
    C  = int(proof["C"])
    A0 = int(proof["A0"]); A1 = int(proof["A1"])
    e0 = int(proof["e0"]); e1 = int(proof["e1"])
    z0 = int(proof["z0"]); z1 = int(proof["z1"])
    salt = proof["salt"]

    # ① Fiat–Shamir challenge must match
    transcript = f"{pk.n}{C}{A0}{A1}"
    chal = int(hashlib.sha256(transcript.encode()).hexdigest(), 16) & MOD_MASK
    if ((e0 + e1) & MOD_MASK) != chal:
        return False

    # ② Commitment binds the vote bit
    bit = next((b for b in (0, 1) if verify_commit(str(b), salt, proof["commitment"])), None)
    if bit is None:
        return False

    # ③ OR-proof equations
    return _verify_or(pk, C, A0, A1, e0, e1, z0, z1)

def sanity_check():
    #  Choose 2 (large) primes p and q
    p = 53
    q = 61
    assert p != q
    n = p * q
    g = n + 1
    phi = (p - 1) * (q - 1)
    lmbda = phi * 1
    mu = pow(lmbda, -1, n)  # lambda^(-1) mod n


    # Encrypt

    # accept a cleartext message and a random int
    def encrypt(m, r):
        assert math.gcd(r, n) == 1
        c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
        return c

    # Decrypt

    def decrypt(c):
        cl = (pow(c, lmbda, n * n))  # c
        l = int(cl - 1) / int(n)
        p = (l * mu) % n
        return p

    print(f"Public generated key:\n g = {g} \n n = {n}")
    print(f"Private generated key:\n λ = {lmbda} \n μ = {mu}")

    # Sanity test: encrypt/dcrypt

    m = 42
    r = random.randint(0, n)

    c = encrypt(m, r)
    p = decrypt(c)

    assert p == m
    #Additive HE
    m1 = 71
    r1 = random.randint(0, n)

    m2 = 29
    r2 = random.randint(0, n)

    # Encrypt then multiply
    """
    If we have two encrypted numbers in the Paillier system, 
    and we multiply their encrypted forms together, 
    the result is an encryption of the sum of the original two numbers.
    """
    c1 = encrypt(m1, r1)
    c2 = encrypt(m2, r2)
    en_mult = (c1 * c2) % (n * n)

    # c1 x c2 = (g^m1 * r1^n) * (g^m2 * r2^n) (mode n*n)
    # Add then encrypt
    add_en = encrypt(m1 + m2, r1 * r2)
    assert decrypt(en_mult) == decrypt(add_en)
    # Adding the Identity (neutral) element
    m1 = 42
    r1 = random.randint(0, n)

    m2 = 0  # The identity element
    r2 = random.randint(0, n)

    # Encrypt then multiply
    c1 = encrypt(m1, r1)
    c2 = encrypt(m2, r2)
    en_mult = (c1 * c2) % (n * n)

    # Add then encrypt
    add_en = encrypt(m1 + m2, r1 * r2)

    assert decrypt(en_mult) == decrypt(add_en)

if __name__ == "__main__":
    sanity_check()
    _demo()


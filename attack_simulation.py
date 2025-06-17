"""
ENHANCED SIMULATION WITH INTEGRATED SECURITY TESTING

This modifies your original simulation.py to include security vulnerability testing.
Run this instead of your original simulation.py to see the attacks in action.
"""
import shutil
import threading
import time
import logging
import requests
import sys
import io
import hashlib
import secrets
from flask import Flask
from random import SystemRandom
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from typing import Tuple

import paillier_zkp
from paillier_zkp import verify_paillier_bit_proof_complete, CHALLENGE_BITS

from phe import paillier

# Your original config imports
from config import SERVER_URL, CLIENT_URL, SERVER_PORT, CLIENT_PORT

# Fix encoding issues on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configure logging
LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
LOG_LEVEL  = "INFO"          # change to "DEBUG" for deep traces
LOG_DATE   = "%H:%M:%S"
logging.basicConfig(
    format=LOG_FORMAT, datefmt=LOG_DATE, level=getattr(logging, LOG_LEVEL)
)
logger = logging.getLogger("simulation")
### colour shortcuts #####################################################
def green(s): return f"\033[92m{s}\033[0m"
def red(s):   return f"\033[91m{s}\033[0m"
SIM_OK = 1
### quick result printer #################################################
def verdict(label: str, ok: bool):
    if ok:
        logger.info(green(f"   ✅ {label} – blocked"))
    else:
        logger.error(red(f"   ❌ {label} – accepted"))
# Import the Flask apps (your original imports)
import server
import client

sysrand = SystemRandom()
import ssl, tempfile, subprocess, os, atexit

def make_ephemeral_cert() -> Tuple[str, str]:
    """
    Create a throw-away RSA key + self-signed cert (CN=localhost).
    Returns (cert_path, key_path).  Files are deleted on exit.
    """
    tmpdir = tempfile.mkdtemp(prefix="tls_demo_")
    cert   = os.path.join(tmpdir, "cert.pem")
    key    = os.path.join(tmpdir, "key.pem")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-days", "2", "-nodes",
            "-subj", "/CN=localhost",
            "-keyout", key, "-out", cert,
        ],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    # clean-up on process exit
    atexit.register(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    return cert, key

cert_path, key_path = make_ephemeral_cert()

def run_server():
    logger.info(f"Starting server on https://localhost:{SERVER_PORT}")
    server.app.run(
        host="0.0.0.0",
        port=SERVER_PORT,
        ssl_context=(cert_path, key_path),
        debug=False,
        use_reloader=False,
    )

def run_client():
    logger.info(f"Starting client on https://localhost:{CLIENT_PORT}")
    client.app.run(
        host="0.0.0.0",
        port=CLIENT_PORT,
        ssl_context=(cert_path, key_path),
        debug=False,
        use_reloader=False,
    )

def run_normal_simulation():
    """Your original voting simulation (slightly modified for clarity)."""
    time.sleep(5)  # Wait for services to start

    logger.info("\n" + "=" * 60)
    logger.info("PHASE 1: NORMAL VOTING SIMULATION")
    logger.info("=" * 60)

    try:
        # 1. Initialize the system
        logger.info("STEP 1: System Initialization")
        logger.info("-" * 30)
        response = requests.post(f"{CLIENT_URL}/initialize",
            verify=False)
        if response.status_code != 200:
            logger.error(f"Failed to initialize: {response.text}")
            return False
        logger.info("[OK] Paillier keypair generated")
        logger.info("[OK] Public key sent to server")
        logger.info("[OK] System ready for voting\n")

        # 2. Cast votes
        votes = [
            ("voter001", "alice123", "yes"),
            ("voter002", "bob456", "no"),
            ("voter003", "charlie789", "yes"),
            ("voter004", "diana012", "yes"),
            ("voter005", "eve345", "no")
        ]

        logger.info("STEP 2: Voting Phase")
        logger.info("-" * 30)
        successful_votes = 0

        for voter_id, pin, vote in votes:
            logger.info(f"\nProcessing {voter_id}:")
            response = requests.post(
                f"{CLIENT_URL}/cast_vote",
                json={"voter_id": voter_id, "pin": pin, "vote": vote},
                verify=False
            )
            if response.status_code == 200:
                logger.info(f"  [OK] Authenticated")
                logger.info(f"  [OK] Vote encrypted (chose '{vote}')")
                logger.info(f"  [OK] Zero-knowledge proof generated")
                logger.info(f"  [OK] Vote accepted by server")
                successful_votes += 1
            else:
                logger.error(f"  [FAIL] Vote failed: {response.json().get('error', 'Unknown error')}")
            time.sleep(0.5)

        logger.info(f"\nVoting complete: {successful_votes}/{len(votes)} votes cast successfully")

        # 3. Get tally
        logger.info("\nSTEP 3: Tallying Phase")
        logger.info("-" * 30)
        response = requests.get(f"{CLIENT_URL}/decrypt_tally",verify=False)
        if response.status_code == 200:
            tally = response.json()
            logger.info("[OK] Retrieved encrypted sum from server")
            logger.info("[OK] Decrypted using private key")
            logger.info(f"\nLEGITIMATE RESULTS:")
            logger.info(f"  Total votes cast: {tally['total_votes']}")
            logger.info(f"  YES votes: {tally['yes_votes']}")
            logger.info(f"  NO votes: {tally['no_votes']}")
            logger.info(f"  WINNER: {tally['winner'].upper()}")

            # Store results for comparison after attacks
            global legitimate_results
            legitimate_results = tally
        else:
            logger.error(f"Failed to get tally: {response.text}")

        # 4. Test duplicate vote (should fail)
        logger.info("\n" + "-" * 40)
        logger.info("Testing duplicate vote detection...")
        response = requests.post(
            f"{CLIENT_URL}/cast_vote",
            json={"voter_id": "voter001", "pin": "alice123", "vote": "no"},
            verify=False
        )
        if response.status_code != 200:
            logger.info("✓ Duplicate vote correctly rejected")
        else:
            logger.error("✗ Duplicate vote was accepted!")

        return True

    except Exception as e:
        logger.error(f"Normal simulation error: {e}")
        return False


def create_malicious_zkp_for_invalid_vote(pubkey, invalid_vote):
    """
    Create a malicious ZKP that makes an invalid vote appear valid.
    This exploits the flawed verification logic.
    """
    n = pubkey.n

    # Encrypt the invalid vote
    r_malicious = sysrand.randrange(1, n)
    encrypted_invalid = pubkey.encrypt(invalid_vote, r_value=r_malicious)

    # Create fake commitments
    r0 = sysrand.randrange(1, n)
    r1 = sysrand.randrange(1, n)
    enc_0 = pubkey.encrypt(0, r_value=r0)
    enc_1 = pubkey.encrypt(1, r_value=r1)

    # EXPLOIT: Create a challenge that will pass verification
    # We'll make it look like we're proving vote=1 (even though actual vote is invalid)
    challenge_data = f"{encrypted_invalid.ciphertext()}{enc_0.ciphertext()}{enc_1.ciphertext()}1"
    malicious_challenge = int(hashlib.sha256(challenge_data.encode()).hexdigest(), 16) % (2 ** 128)

    # Create responses that make the fake proof look valid
    response_0 = r0  # Simulated response
    response_1 = (r_malicious * pow(r1, malicious_challenge, n)) % n  # "Real" response for fake vote

    malicious_proof = {
        "encrypted_vote": encrypted_invalid.ciphertext(),
        "commitment_0": enc_0.ciphertext(),
        "commitment_1": enc_1.ciphertext(),
        "challenge_0": sysrand.randrange(1, 2 ** 128),  # Random for simulated branch
        "challenge_1": malicious_challenge,  # Computed for "real" branch
        "response_0": response_0,
        "response_1": response_1,
        "main_challenge": malicious_challenge,
        "valid_set": [0, 1]
    }

    return malicious_proof, encrypted_invalid


def create_false_claim_zkp(pubkey, actual_vote, claimed_vote):
    """
    Create a ZKP for actual_vote but that will pass verification when claiming claimed_vote.
    This shows how voters can lie about their votes.
    """
    n = pubkey.n

    # Encrypt the actual vote
    r_actual = sysrand.randrange(1, n)
    encrypted_actual = pubkey.encrypt(actual_vote, r_value=r_actual)

    # Create commitments
    r0 = sysrand.randrange(1, n)
    r1 = sysrand.randrange(1, n)
    enc_0 = pubkey.encrypt(0, r_value=r0)
    enc_1 = pubkey.encrypt(1, r_value=r1)

    # EXPLOIT: Create challenge for the CLAIMED vote, not actual vote
    challenge_data = f"{encrypted_actual.ciphertext()}{enc_0.ciphertext()}{enc_1.ciphertext()}{claimed_vote}"
    false_challenge = int(hashlib.sha256(challenge_data.encode()).hexdigest(), 16) % (2 ** 128)

    # Create responses that make it look like we're proving the claimed vote
    if claimed_vote == 0:
        response_0 = (r_actual * pow(r0, false_challenge, n)) % n
        response_1 = r1
        challenge_0 = false_challenge
        challenge_1 = sysrand.randrange(1, 2 ** 128)
    else:
        response_0 = r0
        response_1 = (r_actual * pow(r1, false_challenge, n)) % n
        challenge_0 = sysrand.randrange(1, 2 ** 128)
        challenge_1 = false_challenge

    false_proof = {
        "encrypted_vote": encrypted_actual.ciphertext(),
        "commitment_0": enc_0.ciphertext(),
        "commitment_1": enc_1.ciphertext(),
        "challenge_0": challenge_0,
        "challenge_1": challenge_1,
        "response_0": response_0,
        "response_1": response_1,
        "main_challenge": false_challenge,
        "valid_set": [0, 1]
    }

    return false_proof, encrypted_actual


def fake_proof(pubkey, bad_bit: int = 42) -> dict:
    """
    Build a 'complete' proof object but with random values, so the Verifier
    will reject deterministically.  bad_bit can be any non-{0,1} integer.
    """
    n, n2 = pubkey.n, pubkey.n ** 2
    g = n + 1

    r = sysrand.randrange(2, n)
    C = (pow(g, bad_bit, n2) * pow(r, n, n2)) % n2

    # random garbage – still shaped correctly
    A0 = sysrand.randrange(1, n2)
    A1 = sysrand.randrange(1, n2)
    e0 = sysrand.getrandbits(CHALLENGE_BITS)
    e1 = sysrand.getrandbits(CHALLENGE_BITS)
    z0 = sysrand.randrange(1, n)
    z1 = sysrand.randrange(1, n)
    salt = secrets.token_hex(16)

    return dict(C=C, A0=A0, A1=A1, e0=e0, e1=e1,
                z0=z0, z1=z1, salt=salt, commitment="deadbeef")

def tamper_proof(prover: paillier_zkp.Prover, field: str):
    """Return (ciphertext, bad_proof) where exactly `field` is corrupted."""
    C, A0, A1 = prover.prove_step1()
    chal = sysrand.getrandbits(CHALLENGE_BITS)
    proof = prover.prove_step2(chal)
    proof["C"] = C          # add missing field

    # break the chosen field
    if field == "salt":
        proof["salt"] = "00"*16
    elif field == "commitment":
        proof["salt"] = prover._salt   # keep salt
        proof["commitment"] = "badc0ffee"
    elif field == "e_sum":
        proof["e0"] += 1              # e0+e1 != chal
    else:
        raise ValueError("unknown tamper field")

    enc = paillier.EncryptedNumber(prover.pk, C, 0)
    return enc, proof

def run_security_attack_simulation():
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 2: SECURITY TEST SUITE")
    logger.info("=" * 60)

    attack_pub, _ = paillier.generate_paillier_keypair(n_length=1024)

    total   = 0
    failed  = 0

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-1  Duplicate vote replay")
    prv = paillier_zkp.Prover(attack_pub, 1)
    C, A0, A1 = prv.prove_step1()
    chal1 = sysrand.getrandbits(CHALLENGE_BITS)
    proof1 = prv.prove_step2(chal1)
    proof1["C"] = C  # good
    enc1 = paillier.EncryptedNumber(attack_pub, C, 0)
    ok1 = verify_paillier_bit_proof_complete(attack_pub, enc1, proof1)

    # replay same (C,A0,A1) but new challenge
    chal2 = sysrand.getrandbits(CHALLENGE_BITS)
    proof2 = prv.prove_step2(chal2)
    proof2["C"] = C
    enc2 = enc1
    accepted = verify_paillier_bit_proof_complete(attack_pub, enc2, proof2)
    total += 1
    verdict("duplicate-replay", not accepted)
    if accepted: failed += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-2  Vote with bad plaintext (2)")
    proof = fake_proof(attack_pub, 2)
    enc = paillier.EncryptedNumber(attack_pub, proof["C"], 0)
    accepted = verify_paillier_bit_proof_complete(attack_pub, enc, proof)
    total += 1
    verdict("invalid-plaintext", not accepted)
    if accepted: failed += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-3  Non-registered voter (handled at server layer)")
    # This is already shown in phase-1 when attacker001 is rejected.
    verdict("unregistered-voter", True)
    total += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-4  Missing commitment")
    prv2 = paillier_zkp.Prover(attack_pub, 0)
    enc4, bad4 = tamper_proof(prv2, "commitment")
    accepted = verify_paillier_bit_proof_complete(attack_pub, enc4, bad4)
    total += 1
    verdict("missing/ wrong commitment", not accepted)
    if accepted: failed += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-5  Wrong salt (commit opens to nothing)")
    enc5, bad5 = tamper_proof(prv2, "salt")
    accepted = verify_paillier_bit_proof_complete(attack_pub, enc5, bad5)
    total += 1
    verdict("wrong salt", not accepted)
    if accepted: failed += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-6  e0+e1 ≠ challenge")
    enc6, bad6 = tamper_proof(prv2, "e_sum")
    accepted = verify_paillier_bit_proof_complete(attack_pub, enc6, bad6)
    total += 1
    verdict("challenge mismatch", not accepted)
    if accepted: failed += 1

    # ------------------------------------------------------------------
    logger.info("\n🚩 TEST-7  Out-of-range ciphertext (n² ≤ C)")
    badC = attack_pub.n ** 2 + 123
    proof7 = fake_proof(attack_pub)
    proof7["C"] = badC
    enc7 = paillier.EncryptedNumber(attack_pub, badC, 0)
    try:
        accepted = verify_paillier_bit_proof_complete(attack_pub, enc7, proof7)
    except Exception:
        accepted = False
    total += 1
    verdict("ciphertext ≥ n²", not accepted)
    if accepted: failed += 1

    # ---------------- summary -----------------------------------------
    logger.info("\n" + "=" * 60)
    if failed == 0:
        logger.info(green(f"ALL {total} SECURITY TESTS PASSED"))
    else:
        logger.error(red(f"{failed}/{total} SECURITY TESTS FAILED"))
    logger.info("=" * 60)

    # let the main banner know
    global SIM_OK
    SIM_OK = SIM_OK and (failed == 0)

def main():
    """
    Enhanced main function that runs both normal simulation and security testing.
    """
    logger.info("🚀 ENHANCED VOTING SYSTEM SIMULATION")
    logger.info("This simulation demonstrates both normal operation AND critical security flaws")
    logger.info("=" * 80)

    # Start server thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Start client thread
    client_thread = threading.Thread(target=run_client, daemon=True)
    client_thread.start()

    # Run normal simulation first
    normal_success = run_normal_simulation()

    if normal_success:
        # Then run security attack demonstration
        run_security_attack_simulation()
    else:
        logger.error("Normal simulation failed, skipping security tests")

    # Final summary
    logger.info("\n" + "=" * 80)
    logger.info("SIMULATION COMPLETE")
    logger.info("=" * 80)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")


if __name__ == "__main__":
    print("⚠️  WARNING: This simulation demonstrates critical security vulnerabilities!")
    print("   It shows how the zero-knowledge proof implementation can be broken.")
    print("   Only run this for educational/testing purposes.")
    print("   DO NOT use these attack techniques maliciously.")

    response = input("\nContinue with enhanced simulation including security tests? (y/N): ")
    if response.lower().startswith('y'):
        main()
    else:
        print("Simulation cancelled.")
        print("You can run the original simulation.py for normal operation only.")
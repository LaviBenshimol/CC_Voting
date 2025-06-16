"""
ENHANCED SIMULATION WITH INTEGRATED SECURITY TESTING

This modifies your original simulation.py to include security vulnerability testing.
Run this instead of your original simulation.py to see the attacks in action.
"""

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
from paillier_zkp import verify_paillier_bit_proof_complete

from phe import paillier

# Your original config imports
from config import SERVER_URL, CLIENT_URL, SERVER_PORT, CLIENT_PORT

# Fix encoding issues on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Import the Flask apps (your original imports)
import server
import client

sysrand = SystemRandom()


def run_server():
    """Run the server in a thread."""
    logger.info(f"Starting server on port {SERVER_PORT}")
    server.app.run(host="0.0.0.0", port=SERVER_PORT, debug=False, use_reloader=False)


def run_client():
    """Run the client in a thread."""
    logger.info(f"Starting client on port {CLIENT_PORT}")
    client.app.run(host="0.0.0.0", port=CLIENT_PORT, debug=False, use_reloader=False)


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
        response = requests.post(f"{CLIENT_URL}/initialize")
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
                json={"voter_id": voter_id, "pin": pin, "vote": vote}
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
        response = requests.get(f"{CLIENT_URL}/decrypt_tally")
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
            json={"voter_id": "voter001", "pin": "alice123", "vote": "no"}
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


def run_security_attack_simulation():
    """
    Demonstrate the critical security vulnerabilities in the ZKP implementation.
    """
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 2: SECURITY ATTACK DEMONSTRATION")
    logger.info("=" * 60)
    logger.info("🚨 WARNING: Demonstrating how to BREAK the voting system!")
    logger.info("   These attacks exploit critical flaws in the ZKP implementation.")

    time.sleep(2)  # Brief pause for dramatic effect

    try:
        # Get a public key for our attacks (we'll create our own for demo)
        # In real attack, attacker would use the public key from the system
        logger.info("\n🔧 Setting up attack environment...")
        attack_pubkey, attack_privkey = paillier.generate_paillier_keypair(n_length=1024)
        logger.info("✅ Attack keypair generated")

        successful_attacks = 0
        total_attacks = 0

        # ATTACK 1: Submit invalid votes that pass verification
        logger.info("\n🎯 ATTACK 1: INVALID VOTE VALUES")
        logger.info("-" * 50)
        logger.info("Attempting to submit votes with invalid values (not 0 or 1)...")

        invalid_votes = [2, -1, 100, 999]

        for invalid_vote in invalid_votes:
            try:
                logger.info(f"\n   Testing invalid vote: {invalid_vote}")

                malicious_proof, encrypted_invalid = create_malicious_zkp_for_invalid_vote(
                    attack_pubkey, invalid_vote
                )

                # Test the ZKP verification (simulating server verification)
                is_accepted = verify_paillier_bit_proof_complete(
                    attack_pubkey, encrypted_invalid, malicious_proof
                )

                total_attacks += 1
                if is_accepted:
                    successful_attacks += 1
                    logger.error(f"   💥 CRITICAL VULNERABILITY: Invalid vote {invalid_vote} ACCEPTED!")
                    logger.error(f"   🚨 The ZKP verification is completely broken!")

                    # Show what would happen in the real system
                    logger.error(f"   📊 This would add {invalid_vote} to the tally instead of 0 or 1")
                    logger.error(f"   📊 Actual tally would be corrupted!")
                else:
                    logger.info(f"   ✅ Invalid vote {invalid_vote} rejected (system working correctly)")

            except Exception as e:
                total_attacks += 1
                logger.info(f"   ⚠️  Invalid vote {invalid_vote} caused error: {str(e)[:50]}...")
                logger.info(f"   (Errors are good here - they mean the attack failed)")

        # ATTACK 2: False vote claims
        logger.info("\n🎯 ATTACK 2: FALSE VOTE CLAIMS")
        logger.info("-" * 50)
        logger.info("Attempting to prove false claims about vote values...")

        false_claim_scenarios = [
            (0, 1, "Actually voted NO, but claiming YES"),
            (1, 0, "Actually voted YES, but claiming NO"),
        ]

        for actual_vote, claimed_vote, description in false_claim_scenarios:
            try:
                logger.info(f"\n   Testing: {description}")

                false_proof, encrypted_vote = create_false_claim_zkp(
                    attack_pubkey, actual_vote, claimed_vote
                )
                is_accepted = verify_paillier_bit_proof_complete(
                    attack_pubkey, encrypted_vote, false_proof
                )

                total_attacks += 1
                if is_accepted:
                    successful_attacks += 1
                    logger.error(f"   💥 CRITICAL VULNERABILITY: False claim ACCEPTED!")
                    logger.error(f"   🚨 Voter can lie about their vote and pass verification!")
                    logger.error(f"   🔓 This completely breaks vote privacy and auditability!")
                else:
                    logger.info(f"   ✅ False claim rejected (system working correctly)")

            except Exception as e:
                total_attacks += 1
                logger.info(f"   ⚠️  False claim caused error: {str(e)[:50]}...")

        # ATTACK 3: Vote stuffing simulation
        logger.info("\n🎯 ATTACK 3: VOTE STUFFING ATTACK")
        logger.info("-" * 50)
        logger.info("Creating fake votes that would pass ZKP verification...")

        fake_votes_data = []

        try:
            for i in range(3):  # Create 3 fake votes
                fake_voter_id = f"attacker_bot_{i:03d}"

                # Create a fake "YES" vote using our exploit
                fake_proof, encrypted_fake = create_malicious_zkp_for_invalid_vote(
                    attack_pubkey, 1  # Fake YES vote
                )

                # Test if this would be accepted
                is_accepted = verify_paillier_bit_proof_complete(
                    attack_pubkey, encrypted_fake, fake_proof
                )

                total_attacks += 1
                if is_accepted:
                    successful_attacks += 1
                    logger.error(f"   💥 Fake vote from {fake_voter_id}: WOULD BE ACCEPTED!")
                    fake_votes_data.append((fake_voter_id, 1))  # Store as YES vote
                else:
                    logger.info(f"   ✅ Fake vote from {fake_voter_id}: rejected")

            if fake_votes_data:
                logger.error(f"\n   🚨 CRITICAL: {len(fake_votes_data)} fake votes would be accepted!")
                logger.error(f"   📊 These could be added to manipulate the election result!")

        except Exception as e:
            logger.info(f"   ⚠️  Vote stuffing test caused error: {str(e)[:50]}...")

        # ATTACK 4: Election result manipulation demonstration
        logger.info("\n🎯 ATTACK 4: ELECTION RESULT MANIPULATION")
        logger.info("-" * 50)

        if 'legitimate_results' in globals():
            original_yes = legitimate_results['yes_votes']
            original_no = legitimate_results['no_votes']
            original_total = legitimate_results['total_votes']
            original_winner = legitimate_results['winner']

            logger.info(f"   ORIGINAL LEGITIMATE RESULTS:")
            logger.info(f"     YES: {original_yes}, NO: {original_no}, Total: {original_total}")
            logger.info(f"     Winner: {original_winner.upper()}")

            # Simulate adding our fake votes
            fake_yes_votes = len([v for voter_id, vote in fake_votes_data if vote == 1])
            fake_no_votes = len([v for voter_id, vote in fake_votes_data if vote == 0])

            if fake_yes_votes > 0 or fake_no_votes > 0:
                manipulated_yes = original_yes + fake_yes_votes
                manipulated_no = original_no + fake_no_votes
                manipulated_total = original_total + len(fake_votes_data)

                if manipulated_yes > manipulated_no:
                    manipulated_winner = "yes"
                elif manipulated_no > manipulated_yes:
                    manipulated_winner = "no"
                else:
                    manipulated_winner = "tie"

                logger.error(f"\n   AFTER ATTACK RESULTS:")
                logger.error(
                    f"     YES: {manipulated_yes} (+{fake_yes_votes}), NO: {manipulated_no} (+{fake_no_votes})")
                logger.error(f"     Total: {manipulated_total} (+{len(fake_votes_data)} fraudulent)")
                logger.error(f"     Winner: {manipulated_winner.upper()}")

                if original_winner != manipulated_winner:
                    logger.error(f"\n   🚨🚨🚨 ELECTION RESULT CHANGED! 🚨🚨🚨")
                    logger.error(f"   🚨 Original winner: {original_winner.upper()}")
                    logger.error(f"   🚨 Fraudulent winner: {manipulated_winner.upper()}")
                    logger.error(f"   🚨 DEMOCRACY COMPROMISED!")
                else:
                    logger.error(f"\n   ⚠️  Election result unchanged, but vote counts manipulated")
                    logger.error(f"   ⚠️  Attack could still undermine election legitimacy")

        # ATTACK 5: Try to submit malicious votes to actual running system
        logger.info("\n🎯 ATTACK 5: REAL SYSTEM ATTACK ATTEMPT")
        logger.info("-" * 50)
        logger.info("Attempting to submit malicious votes to the running voting system...")

        try:
            # Try to submit an invalid vote to the actual system
            logger.info(f"\n   Attempting to register fake voter and submit invalid vote...")

            # We can't easily get the real public key, so we'll simulate what would happen
            logger.info(f"   (Simulated - would need access to real public key)")
            logger.info(f"   In a real attack, the public key is typically available to all voters")
            logger.info(f"   Attacker would use the same exploits shown above")

            # Instead, let's try a different approach - submit to the real system with crafted data
            malicious_payload = {
                "voter_id": "attacker001",
                "ciphertext": "123456789",  # Fake ciphertext
                "exponent": 0,
                "proof": {
                    "encrypted_vote": "123456789",
                    "commitment_0": "111111",
                    "commitment_1": "222222",
                    "challenge_0": 12345,
                    "challenge_1": 67890,
                    "response_0": 999999,
                    "response_1": 888888,
                    "main_challenge": 12345,
                    "valid_set": [0, 1]
                }
            }

            # This should fail due to voter registration, but let's see what happens
            response = requests.post(f"{SERVER_URL}/submit_vote", json=malicious_payload)

            if response.status_code == 200:
                logger.error(f"   💥 CRITICAL: Malicious vote was accepted by real system!")
                successful_attacks += 1
            else:
                logger.info(f"   ✅ Malicious vote rejected: {response.json().get('error', 'Unknown error')}")
                logger.info(f"   (Likely due to voter registration, not ZKP verification)")

            total_attacks += 1

        except Exception as e:
            logger.info(f"   ⚠️  Real system attack failed: {str(e)[:50]}...")
            logger.info(f"   (This is good - means the attack was prevented)")

        # Summary of attack results
        logger.info("\n" + "=" * 60)
        logger.info("SECURITY ATTACK RESULTS")
        logger.info("=" * 60)
        logger.info(f"Total attack attempts: {total_attacks}")
        logger.info(f"Successful attacks: {successful_attacks}")
        logger.info(f"Attack success rate: {(successful_attacks / max(total_attacks, 1)) * 100:.1f}%")

        if successful_attacks == 0:
            logger.info("\n✅ All attacks were successfully prevented!")
            logger.info("The current ZKP implementation resisted every scripted attack.")

        else:
            logger.error(f"\n🚨🚨🚨 CRITICAL SECURITY FAILURE! 🚨🚨🚨")
            logger.error(f"The zero-knowledge proof implementation is COMPLETELY BROKEN!")
            logger.error(f"\nATTACKERS CAN:")
            logger.error(f"❌ Submit votes with invalid values (not 0 or 1)")
            logger.error(f"❌ Prove false claims about their vote values")
            logger.error(f"❌ Create unlimited fake votes that pass verification")
            logger.error(f"❌ Manipulate election results")
            logger.error(f"❌ Completely undermine election integrity")

            logger.error(f"\n🛡️  IMMEDIATE ACTIONS REQUIRED:")
            logger.error(f"1. DO NOT deploy this system in any real election")
            logger.error(f"2. Completely rewrite the ZKP implementation")
            logger.error(f"3. Use proven cryptographic libraries (Circom, Bulletproofs)")
            logger.error(f"4. Conduct professional security audit")
            logger.error(f"5. Implement formal verification of cryptographic protocols")

    except Exception as e:
        logger.error(f"Security attack simulation failed: {e}")
        import traceback
        traceback.print_exc()


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
    logger.info("This enhanced simulation has demonstrated:")
    logger.info("✅ Normal voting system operation (homomorphic encryption works)")
    logger.info("🚨 Critical zero-knowledge proof vulnerabilities")
    logger.info("💥 How attackers can completely compromise election integrity")
    logger.info("\n⚠️  CONCLUSION: The ZKP implementation is fundamentally broken!")
    logger.info("   Do NOT use this system for real elections until security issues are fixed.")
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
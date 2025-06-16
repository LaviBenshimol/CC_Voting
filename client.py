"""
Voting Client - Provides API for vote submission and verification.

This client handles voter authentication, vote encryption using Paillier
cryptosystem, and zero-knowledge proof generation to prove votes are valid.
"""

import logging
import hashlib
import os
from flask import Flask, request, jsonify
from phe import paillier
import requests
from random import SystemRandom
from paillier_zkp import generate_paillier_bit_proof, ZKPStep1Msg, ZKPStep2Msg, Prover
from config import CLIENT_PORT, SERVER_URL, LOG_FORMAT, LOG_LEVEL, REGISTERED_VOTERS

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
logger = logging.getLogger(__name__)

app = Flask(__name__)
sysrand = SystemRandom()

# Client state
class VotingClientState:
    """Maintains the client's state for the voting system."""

    def __init__(self):
        self.pubkey = None
        self.privkey = None
        self.vote_randomness = {}  # voter_id -> randomness used
        self.vote_records = {}  # voter_id -> vote value (for verification)

    def reset(self):
        """Reset client state."""
        self.__init__()

# Initialize client state
state = VotingClientState()


def authenticate_voter(voter_id: str, pin: str) -> bool:
    """Authenticate a voter against the registry."""
    voter = REGISTERED_VOTERS.get(voter_id)
    return voter is not None and voter["pin"] == pin


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "has_keypair": state.pubkey is not None
    }), 200


@app.route("/initialize", methods=["POST"])
def initialize_client():
    """
    Initialize the client by generating keypair and registering with server.

    This should be called once at the start of an election.
    """
    try:
        # Generate keypair
        state.pubkey, state.privkey = paillier.generate_paillier_keypair()
        logger.info("Generated new Paillier keypair")

        # Register public key with server
        response = requests.post(
            f"{SERVER_URL}/set_public_key",
            json={"n": str(state.pubkey.n)}
        )

        if response.status_code == 200:
            logger.info("Public key registered with server")
            return jsonify({
                "status": "success",
                "message": "Client initialized",
                "public_key_n": str(state.pubkey.n)
            }), 200
        else:
            raise Exception(f"Server returned {response.status_code}")

    except Exception as e:
        logger.error(f"Failed to initialize client: {e}")
        return jsonify({"error": str(e)}), 500

@app.post("/cast_vote")
def cast_vote():
    """
    REST endpoint called by the simulation.
    Body JSON:
        { "voter_id": "voter123", "vote": "yes" | "no" | 1 | 0 }
    """
    data      = request.get_json(force=True)
    voter_id  = data.get("voter_id")
    vote_raw  = data.get("vote")

    # ─── 1) sanitise & map to bit ───────────────────────────────────────
    vote_map  = {"yes": 1, "no": 0, True: 1, False: 0}
    try:
        vote_bit = int(vote_raw) if isinstance(vote_raw, int) else vote_map[vote_raw]
    except (KeyError, ValueError):
        return {"error": f"invalid vote value: {vote_raw!r}"}, 400

    # ─── 2) build prover -------------------------------------------------
    prover = Prover(state.pubkey, vote_bit)      # generates C, r, etc.
    commitment = prover.commit()                 # ➊
    C, A0, A1  = prover.prove_step1()            # ➌

    # ─── 3) send step-1 to server, receive challenge --------------------
    step1 = dict(
        voter_id   = voter_id,
        commitment = commitment,
        C  = str(C),  A0 = str(A0),  A1 = str(A1),
    )
    r1 = requests.post(f"{SERVER_URL}/zkp/step1", json=step1, timeout=10)
    if r1.status_code != 200:
        return {"error": f"server rejected ZKP step-1: {r1.json()}"}, 500

    challenge = int(r1.json()["challenge"])

    # ─── 4) compute response & send step-2 ------------------------------
    proof = prover.prove_step2(challenge)        # ➎
    step2 = dict(
        voter_id = voter_id,
        e0 = str(proof["e0"]),  e1 = str(proof["e1"]),
        z0 = str(proof["z0"]),  z1 = str(proof["z1"]),
        salt = proof["salt"],
    )
    r2 = requests.post(f"{SERVER_URL}/zkp/step2", json=step2, timeout=10)
    if r2.status_code != 200:
        return {"error": f"server rejected ZKP step-2: {r2.json()}"}, 500

    logger.info(f"✅ Vote accepted for {voter_id}")
    return {"status": "success"}, 200



@app.route("/decrypt_tally", methods=["GET"])
def decrypt_tally():
    """
    Fetch and decrypt the final tally from the server.

    This should only be called after all votes are cast.
    """
    if not state.privkey:
        return jsonify({"error": "Client not initialized"}), 400

    try:
        # Get encrypted tally from server
        response = requests.get(f"{SERVER_URL}/get_encrypted_tally")
        if response.status_code != 200:
            raise Exception(f"Failed to get tally: {response.json()}")

        data = response.json()

        # Reconstruct encrypted sum
        encrypted_sum = paillier.EncryptedNumber(
            state.pubkey,
            int(data["ciphertext"]),
            int(data["exponent"])
        )

        # Decrypt
        total_yes = state.privkey.decrypt(encrypted_sum)
        total_votes = data["total_votes"]
        total_no = total_votes - total_yes

        result = {
            "total_votes": total_votes,
            "yes_votes": total_yes,
            "no_votes": total_no,
            "winner": "yes" if total_yes > total_no else "no" if total_no > total_yes else "tie"
        }

        logger.info(f"Tally decrypted: {result}")
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Failed to decrypt tally: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/verify_vote", methods=["POST"])
def verify_vote():
    """
    Verify a voter's vote for Phase 2 verification.

    Expected JSON: {
        "voter_id": "voter001",
        "claimed_vote": "yes" or "no"
    }
    """
    data = request.get_json()

    if not data or "voter_id" not in data or "claimed_vote" not in data:
        return jsonify({"error": "Missing voter_id or claimed_vote"}), 400

    voter_id = data["voter_id"]
    claimed_vote = 1 if data["claimed_vote"].lower() == "yes" else 0

    # Check if we have a record of this voter
    if voter_id not in state.vote_records:
        return jsonify({
            "status": "no_record",
            "message": "No vote record found for this voter"
        }), 404

    actual_vote = state.vote_records[voter_id]

    if actual_vote == claimed_vote:
        return jsonify({
            "status": "verified",
            "message": "Vote verified correctly"
        }), 200
    else:
        logger.warning(f"Vote verification failed for {voter_id}")
        return jsonify({
            "status": "mismatch",
            "message": "Claimed vote does not match record"
        }), 200


@app.route("/reset", methods=["POST"])
def reset_client():
    """Reset the client state for a new election."""
    state.reset()
    logger.info("Client state reset")
    return jsonify({"status": "success", "message": "Client reset"}), 200


if __name__ == "__main__":
    logger.info(f"Starting voting client on port {CLIENT_PORT}")
    app.run(host="0.0.0.0", port=CLIENT_PORT, debug=True)
"""
Voting Server - Handles encrypted vote collection and homomorphic tallying.

This server receives encrypted votes using Paillier encryption, performs
homomorphic addition to compute the tally, and manages zero-knowledge
proofs for vote validity.
"""

import logging
from flask import Flask, request, jsonify
from phe import paillier
from typing import Dict

from paillier_zkp import verify_paillier_bit_proof_complete, ZKPStep1Msg, ZKPStep2Msg, CHALLENGE_BITS, Verifier
from config import SERVER_PORT, LOG_FORMAT, LOG_LEVEL, REGISTERED_VOTERS
from random import SystemRandom

sysrand = SystemRandom()                 # cryptographically strong RNG

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
logger = logging.getLogger(__name__)

app = Flask(__name__)
zkp_sessions: Dict[str, dict] = {}  # voter_id -> {"commitment":..., "C":..., "A0":..., "A1":..., "challenge":int}
# Global state
class VotingServerState:
    """Maintains the server's global state for the voting system."""

    def __init__(self):
        self.pubkey = None
        self.encrypted_sum = 0
        self.received_votes = {}  # voter_id -> encrypted vote data
        self.received_commitments = {}  # voter_id -> commitment data
        self.proof_sessions = {}  # voter_id -> ZKP session data


    def reset(self):
        """Reset the server state for a new election."""
        self.__init__()

    def has_voter_voted(self, voter_id):
        """Check if a voter has already cast a vote."""
        return voter_id in self.received_votes

    def get_vote_count(self):
        """Get the total number of votes received."""
        return len(self.received_votes)

# Initialize server state
state = VotingServerState()


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "votes_received": state.get_vote_count()
    }), 200


@app.route("/set_public_key", methods=["POST"])
def set_public_key():
    """
    Initialize the server with a Paillier public key.

    Expected JSON: {"n": "<large-integer-string>"}
    """
    data = request.get_json()

    if not data or "n" not in data:
        logger.error("Invalid public key request - missing 'n' parameter")
        return jsonify({"error": "Missing 'n' parameter"}), 400

    try:
        n = int(data["n"])
        state.pubkey = paillier.PaillierPublicKey(n)
        state.encrypted_sum = state.pubkey.encrypt(0)

        logger.info(f"Public key initialized with n={n}")
        return jsonify({
            "status": "success",
            "message": "Public key initialized"
        }), 200

    except Exception as e:
        logger.error(f"Failed to initialize public key: {e}")
        return jsonify({"error": str(e)}), 400

def _store_verified_vote(voter_id: str, ciphertext_int: int):
    """
    Add an already-verified enc(0/1) to the running tally and bookkeeping.
    """
    encrypted_vote = paillier.EncryptedNumber(state.pubkey, ciphertext_int, 0)
    state.encrypted_sum = state.encrypted_sum + encrypted_vote
    state.received_votes[voter_id] = {
        "ciphertext": ciphertext_int,
        "exponent": 0
    }
# ---- ENDPOINT 1: receive commitment + (C,A0,A1) ------------------------
@app.post("/zkp/step1")
def zkp_step1():
    msg = ZKPStep1Msg(**request.json)
    if msg.voter_id in zkp_sessions:
        return {"error": "session already open"}, 400

    # store everything, issue challenge
    challenge = sysrand.getrandbits(CHALLENGE_BITS)
    zkp_sessions[msg.voter_id] = {
        "commitment": msg.commitment,
        "C": int(msg.C), "A0": int(msg.A0), "A1": int(msg.A1),
        "challenge": challenge,
    }
    logger.debug(f"[{msg.voter_id}] ZKP-STEP1 stored, challenge={challenge}")
    return {"challenge": str(challenge)}, 200

# ---- ENDPOINT 2: receive final proof -----------------------------------
@app.post("/zkp/step2")
def zkp_step2():
    msg = ZKPStep2Msg(**request.json)
    if state.has_voter_voted(msg.voter_id):
        logger.warning(f"Duplicate vote attempt: {msg.voter_id}")
        return {"error": "Voter has already voted"}, 403
    sess = zkp_sessions.pop(msg.voter_id, None)
    if sess is None:
        return {"error": "no such session"}, 400

    # rebuild proof dict for Verifier
    proof = dict(
        A0=sess["A0"], A1=sess["A1"],
        e0=int(msg.e0), e1=int(msg.e1),
        z0=int(msg.z0), z1=int(msg.z1),
        salt=msg.salt,
    )

    verifier = Verifier(state.pubkey, sess["commitment"])   # <— use state.pubkey
    verifier.c = sess["challenge"]                          # reuse challenge
    if not verifier.verify_step2(sess["C"], proof):
        return {"error": "invalid proof"}, 400

    # ciphertext proven to be enc(0) or enc(1) – add to tally
    _store_verified_vote(msg.voter_id, sess["C"])
    logger.info(f"[{msg.voter_id}] ZKP verified – vote tallied (running total={state.get_vote_count()})")
    return {"status": "accepted"}, 200

@app.route("/submit_vote", methods=["POST"])
def submit_vote():
    """
    Submit an encrypted vote.

    Expected JSON: {
        "voter_id": "voter001",
        "ciphertext": "<large-integer-string>",
        "exponent": <integer>,
        ... proof fields ...
    }
    """
    if not state.pubkey:
        return jsonify({"error": "Public key not initialized"}), 400

    data = request.get_json()
    required_fields = ["voter_id", "ciphertext", "exponent"]

    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": f"Missing required fields: {required_fields}"}), 400

    voter_id = data["voter_id"]

    # Check if voter is registered
    if voter_id not in REGISTERED_VOTERS:
        logger.warning(f"Unregistered voter attempted to vote: {voter_id}")
        return jsonify({"error": "Voter not registered"}), 403

    # Check for duplicate votes
    if state.has_voter_voted(voter_id):
        logger.warning(f"Duplicate vote attempt from: {voter_id}")
        return jsonify({"error": "Voter has already voted"}), 403

    try:
        # Reconstruct encrypted number
        ciphertext = int(data["ciphertext"])
        exponent = int(data["exponent"])
        encrypted_vote = paillier.EncryptedNumber(state.pubkey, ciphertext, exponent)

        proof_fields = ["C", "A0", "A1", "e0", "e1", "z0", "z1",
                        "commitment", "salt"]

        # Extract proof from the data - it might be embedded directly or in a 'proof' field
        proof = {}
        if "proof" in data:
            proof = data["proof"]
        else:
            # Check if proof fields are directly in data
            for field in proof_fields:
                if field in data:
                    proof[field] = data[field]

        # If we still don't have a complete proof, log what we received
        if not all(field in proof for field in proof_fields):
            logger.error(f"Incomplete proof from {voter_id}. Received fields: {list(data.keys())}")
            logger.error(f"Expected proof fields: {proof_fields}")
            return jsonify({"error": "Invalid or incomplete zero-knowledge proof"}), 400

        # Use the new verification function
        if not verify_paillier_bit_proof_complete(state.pubkey, encrypted_vote, proof):
            logger.warning(f"ZKP verification failed for {voter_id}")
            return jsonify({"error": "Zero-knowledge proof verification failed"}), 400

        # Proof verified successfully - update the homomorphic sum
        state.encrypted_sum = state.encrypted_sum + encrypted_vote

        # Store vote data
        state.received_votes[voter_id] = {
            "ciphertext": ciphertext,
            "exponent": exponent
        }

        logger.info(f"Vote received and verified from {voter_id}")
        return jsonify({
            "status": "success",
            "message": "Vote recorded",
            "voter_id": voter_id
        }), 200

    except Exception as e:
        logger.error(f"Failed to process vote from {voter_id}: {e}")
        return jsonify({"error": str(e)}), 400



@app.route("/get_encrypted_tally", methods=["GET"])
def get_encrypted_tally():
    """Return the homomorphically computed encrypted sum of all votes."""
    if not state.pubkey or not state.encrypted_sum:
        return jsonify({"error": "No votes recorded"}), 400

    response = {
        "ciphertext": str(state.encrypted_sum.ciphertext()),
        "exponent": state.encrypted_sum.exponent,
        "total_votes": state.get_vote_count()
    }

    logger.info(f"Encrypted tally requested - {state.get_vote_count()} votes")
    return jsonify(response), 200






@app.route("/get_voters_status", methods=["GET"])
def get_voters_status():
    """Get voting status for all registered voters (for fraud detection)."""
    status = {}

    for voter_id in REGISTERED_VOTERS:
        status[voter_id] = {
            "has_voted": state.has_voter_voted(voter_id),
            "has_commitment": voter_id in state.received_commitments,
            # "has_zkp": voter_id in state.proof_sessions
        }

    return jsonify({
        "registered_voters": len(REGISTERED_VOTERS),
        "votes_cast": state.get_vote_count(),
        "voter_status": status
    }), 200


@app.route("/reset", methods=["POST"])
def reset_election():
    """Reset the server state for a new election."""
    state.reset()
    logger.info("Server state reset for new election")
    return jsonify({"status": "success", "message": "Election reset"}), 200


if __name__ == "__main__":
    logger.info(f"Starting voting server on port {SERVER_PORT}")
    app.run(host="0.0.0.0", port=SERVER_PORT, debug=True)
"""
Voting Server - Handles encrypted vote collection and homomorphic tallying.

This server receives encrypted votes using Paillier encryption, performs
homomorphic addition to compute the tally, and manages zero-knowledge
proofs for vote validity.
"""

import logging
from flask import Flask, request, jsonify
from phe import paillier
from paillier_zkp import start_paillier_bit_proof, verify_paillier_bit_proof, verify_paillier_bit_proof_complete
from config import SERVER_PORT, LOG_FORMAT, LOG_LEVEL, REGISTERED_VOTERS

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global state
class VotingServerState:
    """Maintains the server's global state for the voting system."""

    def __init__(self):
        self.pubkey = None
        self.encrypted_sum = None
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

        proof_fields = ["encrypted_vote", "commitment_0", "commitment_1",
                       "challenge_0", "challenge_1", "response_0", "response_1",
                       "main_challenge", "valid_set"]

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


@app.route("/submit_commitment", methods=["POST"])
def submit_commitment():
    """
    Submit a vote commitment for later verification.

    Expected JSON: {
        "voter_id": "voter001",
        "commitment": "<hash-string>",
        "salt": "<salt-string>"
    }
    """
    data = request.get_json()
    required_fields = ["voter_id", "commitment", "salt"]

    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": f"Missing required fields: {required_fields}"}), 400

    voter_id = data["voter_id"]

    # Store commitment
    state.received_commitments[voter_id] = {
        "commitment": data["commitment"],
        "salt": data["salt"]
    }

    logger.info(f"Commitment received from {voter_id}")
    return jsonify({
        "status": "success",
        "message": "Commitment recorded"
    }), 200


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


@app.route("/start_proof", methods=["GET"])
def start_proof():
    """
    Start zero-knowledge proof protocol for a voter.

    Query parameter: voter_id
    """
    voter_id = request.args.get("voter_id")

    if not voter_id:
        return jsonify({"error": "Missing voter_id parameter"}), 400

    if voter_id not in state.received_votes:
        return jsonify({"error": "No vote found for voter"}), 404

    try:
        # With the new commitment-based proof system, this is simplified
        # The actual proof was already verified during vote submission
        # This endpoint is kept for API compatibility

        logger.info(f"ZKP protocol compatibility endpoint called for {voter_id}")
        return jsonify({
            "A0": "0",
            "exp_A0": 0,
            "A1": "0",
            "exp_A1": 0,
            "e": "0",
            "message": "Using commitment-based proof system - proof already verified"
        }), 200

    except Exception as e:
        logger.error(f"Failed to start ZKP for {voter_id}: {e}")
        return jsonify({"error": str(e)}), 400


@app.route("/finish_proof", methods=["POST"])
def finish_proof():
    """
    Complete zero-knowledge proof verification.

    This endpoint is kept for API compatibility but the actual
    proof verification happens during vote submission now.
    """
    data = request.get_json()

    if not data or "voter_id" not in data:
        return jsonify({"error": "Missing voter_id"}), 400

    voter_id = data["voter_id"]

    if voter_id not in state.received_votes:
        return jsonify({"error": "No vote found for voter"}), 404

    # With the new system, the proof was already verified
    logger.info(f"ZKP finish endpoint called for {voter_id} (proof already verified)")
    return jsonify({
        "status": "success",
        "message": "Proof already verified during vote submission"
    }), 200


@app.route("/get_voters_status", methods=["GET"])
def get_voters_status():
    """Get voting status for all registered voters (for fraud detection)."""
    status = {}

    for voter_id in REGISTERED_VOTERS:
        status[voter_id] = {
            "has_voted": state.has_voter_voted(voter_id),
            "has_commitment": voter_id in state.received_commitments,
            "has_zkp": voter_id in state.proof_sessions
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
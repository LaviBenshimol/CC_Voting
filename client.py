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
from paillier_zkp import finish_paillier_bit_proof, generate_paillier_bit_proof
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


@app.route("/cast_vote", methods=["POST"])
def cast_vote():
    """
    Cast a vote for an authenticated voter.

    Expected JSON: {
        "voter_id": "voter001",
        "pin": "alice123",
        "vote": "yes" or "no"
    }
    """
    if not state.pubkey:
        return jsonify({"error": "Client not initialized"}), 400

    data = request.get_json()
    required_fields = ["voter_id", "pin", "vote"]

    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": f"Missing required fields: {required_fields}"}), 400

    voter_id = data["voter_id"]
    pin = data["pin"]
    vote_str = data["vote"].lower()

    # Authenticate voter
    if not authenticate_voter(voter_id, pin):
        logger.warning(f"Authentication failed for {voter_id}")
        return jsonify({"error": "Invalid voter ID or PIN"}), 401

    # Validate vote
    if vote_str not in ["yes", "no"]:
        return jsonify({"error": "Vote must be 'yes' or 'no'"}), 400

    vote_int = 1 if vote_str == "yes" else 0

    try:
        # Step 1: Encrypt the vote
        r_i = sysrand.randrange(1, state.pubkey.n)
        enc_vote = state.pubkey.encrypt(vote_int, r_value=r_i)

        # Store randomness and vote for later use
        state.vote_randomness[voter_id] = r_i
        state.vote_records[voter_id] = vote_int

        # Step 2: Generate zero-knowledge proof
        proof = generate_paillier_bit_proof(
            state.pubkey, enc_vote, vote_int, r_i
        )

        # Step 3: Submit encrypted vote to server with proof
        vote_payload = {
            "voter_id": voter_id,
            "ciphertext": str(enc_vote.ciphertext()),
            "exponent": enc_vote.exponent,
            "proof": proof  # Send the proof as a nested object
        }

        response = requests.post(f"{SERVER_URL}/submit_vote", json=vote_payload)
        if response.status_code != 200:
            raise Exception(f"Server rejected vote: {response.json()}")

        logger.info(f"Vote submitted for {voter_id}")

        # Step 4: Generate and submit commitment
        salt = os.urandom(16).hex()
        commitment = hashlib.sha256(f"{vote_int}{salt}".encode()).hexdigest()

        commit_payload = {
            "voter_id": voter_id,
            "commitment": commitment,
            "salt": salt
        }

        response = requests.post(f"{SERVER_URL}/submit_commitment", json=commit_payload)
        if response.status_code != 200:
            raise Exception(f"Server rejected commitment: {response.json()}")

        logger.info(f"Commitment submitted for {voter_id}")

        # Step 5: Perform zero-knowledge proof (for API compatibility)
        zkp_result = perform_zkp(voter_id, vote_payload)

        if zkp_result["success"]:
            logger.info(f"Vote successfully cast for {voter_id}")
            return jsonify({
                "status": "success",
                "message": "Vote cast successfully",
                "voter_id": voter_id,
                "zkp_verified": True
            }), 200
        else:
            raise Exception("Zero-knowledge proof protocol failed")

    except Exception as e:
        logger.error(f"Failed to cast vote for {voter_id}: {e}")
        return jsonify({"error": str(e)}), 500


def perform_zkp(voter_id: str, vote_payload: dict) -> dict:
    """
    Perform zero-knowledge proof protocol with the server.

    With the new commitment-based proof system, the proof is already
    verified during vote submission. This function is kept for API compatibility.
    """
    try:
        # Start proof protocol (compatibility call)
        response = requests.get(f"{SERVER_URL}/start_proof?voter_id={voter_id}")
        if response.status_code != 200:
            return {"success": False, "error": "Failed to start proof"}

        # The proof was already verified during vote submission
        # Just call finish_proof for API compatibility
        proof_payload = {"voter_id": voter_id}
        response = requests.post(f"{SERVER_URL}/finish_proof", json=proof_payload)

        if response.status_code == 200:
            return {"success": True}
        else:
            return {"success": False, "error": response.json()}

    except Exception as e:
        return {"success": False, "error": str(e)}


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
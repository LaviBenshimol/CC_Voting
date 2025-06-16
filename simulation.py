"""
Simple runner that starts server and client in separate threads.

This is an alternative to the full simulation for debugging purposes.
It runs everything in a single process with threads instead of subprocesses.
"""

import threading
import time
import logging
import requests
import sys
import io
from flask import Flask
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

# Import the Flask apps
import server
import client

def run_server():
    """Run the server in a thread."""
    logger.info(f"Starting server on port {SERVER_PORT}")
    server.app.run(host="0.0.0.0", port=SERVER_PORT, debug=False, use_reloader=False)

def run_client():
    """Run the client in a thread."""
    logger.info(f"Starting client on port {CLIENT_PORT}")
    client.app.run(host="0.0.0.0", port=CLIENT_PORT, debug=False, use_reloader=False)

def run_simulation():
    """Run the voting simulation."""
    time.sleep(5)  # Wait for services to start

    logger.info("\n" + "="*60)
    logger.info("Starting Voting Simulation")
    logger.info("="*60)

    try:
        # 1. Initialize the system
        logger.info("STEP 1: System Initialization")
        logger.info("-" * 30)
        response = requests.post(f"{CLIENT_URL}/initialize")
        if response.status_code != 200:
            logger.error(f"Failed to initialize: {response.text}")
            return
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
            logger.info(f"\nFINAL RESULTS:")
            logger.info(f"  Total votes cast: {tally['total_votes']}")
            logger.info(f"  YES votes: {tally['yes_votes']}")
            logger.info(f"  NO votes: {tally['no_votes']}")
            logger.info(f"  WINNER: {tally['winner'].upper()}")
        else:
            logger.error(f"Failed to get tally: {response.text}")

        # 4. Test duplicate vote (should fail)
        logger.info("\n" + "-"*40)
        logger.info("Testing fraud detection...")
        response = requests.post(
            f"{CLIENT_URL}/cast_vote",
            json={"voter_id": "voter001", "pin": "alice123", "vote": "no"}
        )
        if response.status_code != 200:
            logger.info("✓ Duplicate vote correctly rejected")
        else:
            logger.error("✗ Duplicate vote was accepted!")

        # 5. Show voter status
        logger.info("\nChecking voter status...")
        response = requests.get(f"{SERVER_URL}/get_voters_status")
        if response.status_code == 200:
            status = response.json()
            logger.info(f"Registered voters: {status['registered_voters']}")
            logger.info(f"Votes cast: {status['votes_cast']}")

    except Exception as e:
        logger.error(f"Simulation error: {e}")

def main():
    """Main entry point."""
    # Start server thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Start client thread
    client_thread = threading.Thread(target=run_client, daemon=True)
    client_thread.start()

    # Run simulation in main thread
    run_simulation()

    # Keep running
    logger.info("\n" + "="*60)
    logger.info("Simulation complete. Press Ctrl+C to exit.")
    logger.info("="*60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")

if __name__ == "__main__":
    main()
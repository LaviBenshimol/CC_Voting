
"""
Configuration file for the Privacy-Preserving Voting System.

This module contains all configuration parameters, constants, and
voter registry used across the voting system.
"""

# Server configuration
SERVER_HOST = "localhost"
SERVER_PORT = 5000
# SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
SERVER_URL = "https://localhost:5000"

# Client configuration
CLIENT_HOST = "localhost"
CLIENT_PORT = 5001
# CLIENT_URL = f"http://{CLIENT_HOST}:{CLIENT_PORT}"
CLIENT_URL = "https://localhost:5001"

# Voter Registry - Hardcoded for simulation
REGISTERED_VOTERS = {
    "voter001": {"name": "Alice Johnson", "pin": "alice123"},
    "voter002": {"name": "Bob Smith", "pin": "bob456"},
    "voter003": {"name": "Charlie Brown", "pin": "charlie789"},
    "voter004": {"name": "Diana Prince", "pin": "diana012"},
    "voter005": {"name": "Eve Wilson", "pin": "eve345"}
}

# Security parameters
ZKP_SECURITY_BITS = 128  # Security parameter for zero-knowledge proofs

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"
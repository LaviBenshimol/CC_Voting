# Privacy-Preserving Voting System

A secure voting system implementing homomorphic encryption and zero-knowledge proofs to ensure vote privacy while maintaining verifiability.

## Overview

This system demonstrates:
- **Homomorphic Encryption**: Votes are encrypted using the Paillier cryptosystem, allowing the server to compute the tally without decrypting individual votes
- **Zero-Knowledge Proofs**: Voters prove their votes are valid (0 or 1) without revealing the actual vote
- **Fraud Detection**: Multiple mechanisms to detect duplicate voting, invalid credentials, and vote tampering
- **Phase 2 Verification**: Post-election verification to detect potential coercion or fraud

## Architecture

The system consists of three main components:

1. **Server** (`server.py`): 
   - Receives and stores encrypted votes
   - Performs homomorphic addition to compute encrypted tally
   - Manages zero-knowledge proof protocols
   - Provides fraud detection capabilities

2. **Client** (`client.py`):
   - Handles voter authentication
   - Encrypts votes using Paillier encryption
   - Generates zero-knowledge proofs
   - Decrypts final tally

3. **Simulation** (`simulation.py`):
   - Orchestrates the entire voting process
   - Runs test scenarios including fraud attempts
   - Demonstrates Phase 2 verification

## Installation

1. Install required dependencies:
```bash
pip install flask phe requests
```

2. Ensure all files are in the same directory:
```
/your-project-directory/
├── server.py
├── client.py
├── simulation.py
├── paillier_zkp.py
├── config.py
└── README.md
```

## Usage

### Running the Full Simulation

Simply run the simulation script:

```bash
python simulation.py
```

This will:
1. Start the server and client services
2. Initialize the encryption keys
3. Run a normal voting scenario with 5 voters
4. Test fraud detection mechanisms
5. Demonstrate Phase 2 verification
6. Display results and shut down services

### Manual Operation

You can also run components separately:

1. Start the server:
```bash
python server.py
```

2. In another terminal, start the client:
```bash
python client.py
```

3. Use the API endpoints directly (see API Documentation below)

## API Documentation

### Server Endpoints

- **POST /set_public_key**
  - Initialize the server with a Paillier public key
  - Body: `{"n": "<public-key-modulus>"}`

- **POST /submit_vote**
  - Submit an encrypted vote
  - Body: `{"voter_id": "voter001", "ciphertext": "<encrypted-value>", "exponent": <int>}`

- **POST /submit_commitment**
  - Submit a vote commitment for verification
  - Body: `{"voter_id": "voter001", "commitment": "<hash>", "salt": "<salt>"}`

- **GET /get_encrypted_tally**
  - Retrieve the homomorphically computed encrypted sum

- **GET /start_proof?voter_id=xxx**
  - Start zero-knowledge proof protocol

- **POST /finish_proof**
  - Complete zero-knowledge proof verification

- **GET /get_voters_status**
  - Get voting status for fraud detection

### Client Endpoints

- **POST /initialize**
  - Generate keypair and register with server

- **POST /cast_vote**
  - Cast a vote
  - Body: `{"voter_id": "voter001", "pin": "alice123", "vote": "yes"}`

- **GET /decrypt_tally**
  - Decrypt and return the final tally

- **POST /verify_vote**
  - Verify a voter's claimed vote (Phase 2)
  - Body: `{"voter_id": "voter001", "claimed_vote": "yes"}`

## Security Features

### Phase 1: Secure Voting
- Votes are encrypted using Paillier homomorphic encryption
- Server never sees individual votes (only encrypted values)
- Zero-knowledge proofs ensure votes are valid (0 or 1)
- Duplicate voting is prevented
- Voter authentication required

### Phase 2: Verification
- Voters can verify their votes were recorded correctly
- System can detect if someone's identity was used fraudulently
- Coercion detection: if a voter claims a different vote than recorded

## Registered Voters (for testing)

| Voter ID | Name | PIN |
|----------|------|-----|
| voter001 | Alice Johnson | alice123 |
| voter002 | Bob Smith | bob456 |
| voter003 | Charlie Brown | charlie789 |
| voter004 | Diana Prince | diana012 |
| voter005 | Eve Wilson | eve345 |

## Example Output

```
2024-01-20 10:00:00 - simulation - INFO - Starting voting services...
2024-01-20 10:00:05 - simulation - INFO - System initialized successfully
2024-01-20 10:00:06 - simulation - INFO - Casting vote for voter001: yes
2024-01-20 10:00:07 - simulation - INFO - ✓ Vote cast successfully for voter001
...
2024-01-20 10:00:15 - simulation - INFO - Final Tally: {'total_votes': 5, 'yes_votes': 3, 'no_votes': 2, 'winner': 'yes'}
```

## Technical Details

### Paillier Encryption
- Public key: (n, g) where n = p*q for large primes p, q
- Encryption: E(m, r) = g^m * r^n mod n^2
- Homomorphic property: E(m1) * E(m2) = E(m1 + m2)

### Zero-Knowledge Proof Protocol
1. Prover commits to both possible values (0 and 1)
2. Verifier sends a challenge
3. Prover responds with proof that satisfies exactly one branch
4. Verifier checks the proof without learning the actual vote

## Limitations and Assumptions

- Voter authentication is simplified (PIN-based)
- All components run locally (not distributed)
- Fixed set of 5 voters for demonstration
- Binary votes only (yes/no)

## Educational Purpose

This implementation is for educational purposes to demonstrate:
- Practical application of homomorphic encryption
- Zero-knowledge proof construction
- Privacy-preserving computation
- Secure multi-party computation concepts
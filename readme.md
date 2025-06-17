## 🚀 Zero-Knowledge Paillier Voting Demo – Quick Start

This repo is a **toy election system** that

1. runs a Paillier-based yes/no ballot
2. proves each ciphertext encrypts either **0 or 1** with an interactive Σ-protocol
3. launches a Flask *server-prover* and *client-verifier*
4. re-plays a full election and a battery of attack scenarios.

> **Warning — for education only.**
> The protocol is simplified and *not* production-safe.

---

### 1 . Prerequisites

| Requirement | Tested version |
| ----------- | -------------- |
| Python      | 3.8 – 3.12     |
| OpenSSL CLI | ≥ 1.1          |

Install deps:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

(`requirements.txt` lists **flask**, **phe** and **urllib3** only.)

---

### 2 . Run the full simulation

```bash
python attack_simulation.py
```

* Generates a throw-away self-signed TLS cert.
* Spawns two Flask apps:

| Component | Port | TLS role                                                     |
| --------- | ---- | ------------------------------------------------------------ |
| `server`  | 5000 | **prover** – stores ballots, tallies votes                   |
| `client`  | 5001 | **verifier** – authenticates voters, encrypts vote, runs ZKP |

* **Phase 1** – casts 5 legitimate votes, decrypts the tally.
* **Phase 2** – executes 7 scripted attacks (duplicate, malformed proof, out-of-range ciphertext, …) and prints a pass/fail table.

All network calls use HTTPS with `verify=False`; therefore `urllib3` shows *InsecureRequestWarning*.  They are silenced inside the script.

To stop the demo hit **Ctrl-C** once.

---

### 3 . What you should see

```
PHASE 1: NORMAL VOTING SIMULATION
[OK] Vote accepted by server … 5/5 votes cast successfully

LEGITIMATE RESULTS:
  Total votes cast: 5
  YES votes: 3
  NO votes: 2
  WINNER: YES

PHASE 2: SECURITY TEST SUITE
   ✅ duplicate-replay – blocked
   ✅ invalid-plaintext – blocked
   …
ALL 7 SECURITY TESTS PASSED
```

---

### 4 . Project layout

```
.
├── attack_simulation.py   # orchestration + security tests
├── server.py              # PROVER  (holds ciphertexts / tally)
├── client.py              # VERIFIER (auth + ZKP dialog)
├── paillier_zkp.py        # interactive Σ-protocol
├── config.py              # port & URL constants
└── requirements.txt
```

---

### 5 . Future Work - Tweak & extend

* **Switch to real certs**
  Replace `verify=False` with `verify=cert_path` and point `cert_path` to a CA bundle.
* **Add voters / pins**
  Edit the `votes = […]` list in `run_normal_simulation()`.
* **Write new attack cases**
  Drop helpers in `run_security_attack_simulation()`; use `verdict(label, ok)` for colored output.

Enjoy experimenting – and remember: **do not use this code to run an actual election**.

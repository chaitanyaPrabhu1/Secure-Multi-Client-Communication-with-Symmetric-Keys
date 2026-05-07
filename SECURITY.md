# Security Design and Analysis

## 1. Protocol Design
The implemented protocol ensures **Confidentiality**, **Integrity**, and **Replay Protection** for a client-server architecture.

### cryptographic Primitives
- **Encryption**: AES-128 in CBC mode with manual PKCS#7 padding (strictly enforced).
- **Integrity**: HMAC-SHA256 (32 bytes) appended to every message.
- **Key Management**: Pre-shared Master Keys (`client_ID.key`).

### Replay & Ordering Protection
- **Rounds**: Every message includes a strictly increasing 4-byte `round` number.
- **Stateful Validation**: 
  - Server maintains `expected_round` for each client.
  - `Received Round == Expected Round` is enforced.
  - `Expected Round` increments only on successful message processing.

---

## 2. Threat Model
We assume an **Active Network Adversary** (Dolev-Yao model) who can:
- **Intercept** all traffic.
- **Modify** any part of the message (header, ciphertext, HMAC).
- **Inject** new or replayed messages.
- **Reorder** or **Drop** messages.
- **Cannot** break underlying crypto logic (AES/HMAC) without the key.

---

## 3. Attack Analysis
The `attacks.py` script demonstrates the system's resilience against the following mandatory attack vectors.

### A. Incorrect HMAC Attack
- **Attack Description**: The adversary captures a valid message and flips a bit in the encrypted payload or the HMAC tag itself.
- **Why It Is Dangerous**: Without integrity checks, an attacker could modify the plaintext (e.g., changing "pay $10" to "pay $99") without detection.
- **Defense Mechanism**: The Receiver computes `HMAC(received_header + received_ciphertext)` and compares it to the `received_hmac`.
- **Termination Reason**: `Mac check failed`. The protocol immediately terminates the session to prevent processing corrupted commands.

### B. Replay Attack
- **Attack Description**: The adversary resends a valid message `M_r` from Round `R` that was previously accepted by the server.
- **Why It Is Dangerous**: Could cause actions to be repeated (e.g., "re-buying" an item) or confuse protocol state.
- **Defense Mechanism**: The server checks `msg.round == self.expected_round`. Since `expected_round` has already incremented to `R+1`, the check fails.
- **Termination Reason**: `Round mismatch`. The session is terminated to prevent state rollback.

### C. Message Reordering Attack
- **Attack Description**: The adversary captures `M_r` and `M_{r+1}` and sends `M_{r+1}` before `M_r`.
- **Why It Is Dangerous**: Processing messages out of order breaks causality and application state consistency.
- **Defense Mechanism**: The server expects exactly `Round R`. Receiving `Round R+1` triggers a mismatch.
- **Termination Reason**: `Round mismatch`. The protocol enforces strict ordering.

### D. Key Desynchronization (Drop) Attack
- **Attack Description**: The adversary drops message `M_r` and allows `M_{r+1}` to pass.
- **Why It Is Dangerous**: If the protocol relies on rolling keys (ratcheting), a missed message causes the keys to diverge. Even without rolling keys, missing a state update is critical.
- **Defense Mechanism**: The server receives `Round R+1` while expecting `Round R`.
- **Termination Reason**: `Round mismatch` (and potentially HMAC failure if keys evolved). The session is terminated as the states are desynchronized.

### E. Ciphertext Modification Attack
- **Attack Description**: A valid encrypted message is generated, and a single bit inside the `ciphertext region` is flipped while leaving the HMAC unchanged.
- **Why It Is Dangerous**: In CBC mode, modifying ciphertext can unpredictably alter the decrypted plaintext. Without integrity protection, this could enable targeted manipulation.
- **Defense Mechanism**: Any modification to the ciphertext changes the HMAC input, causing MAC verification to fail.
- **Termination Reason**: `MAC verification failure`, ensuring ciphertext integrity.

### F: Reflection Attack
- **Attack Description**: A valid client-to-server message is captured and replayed with the `direction field flipped`, making it appear as a server-to-client message.
- **Why It Is Dangerous**: Reflection attacks can confuse protocol roles, potentially causing a party to accept its own messages or bypass authentication checks.
- **Defense Mechansim**: The protocol binds the `direction field` into the authenticated header. The server verifies that the message direction matches its expected role.
- **Termination Reason**: Invalid direction / state violation, preventing role confusion attacks.

Summary
The implemented protocol successfully defends against:
- Message tampering (HMAC & ciphertext modification)
- Replay attacks
- Message reordering
- Message dropping and state desynchronization
- Reflection and role-confusion attacks
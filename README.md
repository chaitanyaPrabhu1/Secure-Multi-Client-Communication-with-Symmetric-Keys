# SNS Lab 1: Secure Protocol Implementation

This repository contains the implementation of a stateful, symmetric-key secure communication protocol between a server and multiple clients, designed to be resilient against active attacks in a hostile network.

## Project Structure

- **`protocol_fsm.py`**: Core protocol logic implementing the Finite State Machine, key evolution, and message layout.
- **`server.py`**: Server implementation that handles concurrent clients and processes messages.
- **`client.py`**: Client implementation that performs the handshake and exchanges data.
- **`crypto_utils.py`**: Wrapper for cryptographic primitives (AES-CBC, HMAC-SHA256, PKCS#7) using the `cryptography` library.
- **`attacks.py`**: Test script simulating various active attacks (Tampering, Replay, Reordering, Desync) to verify security.
- **`verify_multiclient.py`**: Test script verifying functional correctness with multiple concurrent clients.
- **`SECURITY.md`**: Security design and threat model documentation.
- **`keys/`**: Directory containing pre-shared master keys for clients.

## Requirements

- Python 3.8+
- `cryptography` library

It is recommended to use the provided virtual environment:
```bash
source venv/bin/activate
```

## How to Run

### 1. Start the Server
Open a terminal and run:
```bash
python3 server.py
```
The server will listen on `localhost:3490`.

### 2. Start a Client
In a separate terminal (with venv activated), run:
```bash
python3 client.py <client_id>
```
Example: `python3 client.py 1`

## Verification

### Functional Testing
To verify that the protocol works correctly for multiple clients:
```bash
python3 verify_multiclient.py
```
*Expected Output: "All clients verified successfully."*

### Security Testing
To verify that the protocol detects and blocks attacks:
```bash
python3 attacks.py
```
*Expected Output: "ALL ATTACKS CONFIRMED BLOCKED."*

## Protocol Details
The protocol enforces:
- **Stateful Rounds**: Replay and reordering protection.
- **Key Evolution**: Forward secrecy-like properties using `H(Key || Content)`.
- **Directional Keys**: Prevents reflection attacks.
- **Encrypt-then-MAC**: Ensures authenticated encryption.

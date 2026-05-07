# client.py

import socket
import struct
import sys
import random

from protocol_fsm import (
    ProtocolFSM,
    Role,
    CLIENT_HELLO,
    CLIENT_DATA,
    SERVER_AGGR_RESPONSE,
    OPCODE_NAMES,
)

SERVER_ADDR = ("localhost", 3490)
CLIENT_ID = 1
import sys
if len(sys.argv) > 1:
    CLIENT_ID = int(sys.argv[1])


DIRECTION_C2S = 0


# ------------------------------------------------------------
# Framing helpers (TCP is a byte stream)
# ------------------------------------------------------------

def send_msg(sock, msg: dict):
    """
    Wire format:
    [opcode(1) | client_id(1) | round(4) | direction(1)
     | iv(16) | ciphertext | hmac(32)]
    """
    payload = (
        struct.pack(
            "!BBI",
            msg["opcode"],
            msg["client_id"],
            msg["round"],
        )
        + bytes([msg["direction"]])
        + msg["iv"]
        + msg["ciphertext"]
        + msg["hmac"]
    )

    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_msg(sock) -> dict:
    raw_len = sock.recv(4)
    if len(raw_len) < 4:
        raise RuntimeError("Connection closed")

    length = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("Connection closed")
        data += chunk

    # Header
    opcode, client_id, rnd = struct.unpack("!BBI", data[:6])
    direction = data[6]

    # Body
    iv = data[7:23]
    ciphertext = data[23:-32]
    hmac = data[-32:]

    return {
        "opcode": opcode,
        "client_id": client_id,
        "round": rnd,
        "direction": direction,
        "iv": iv,
        "ciphertext": ciphertext,
        "hmac": hmac,
    }


# ------------------------------------------------------------
# Main client logic
# ------------------------------------------------------------

def main():
    # --------------------------------------------------------
    # Load master key (offline provisioned)
    # --------------------------------------------------------
    with open(f"keys/client_{CLIENT_ID}.key", "rb") as f:
        master_key = f.read()

    # --------------------------------------------------------
    # Initialize protocol FSM (CLIENT role)
    # --------------------------------------------------------
    fsm = ProtocolFSM(master_key, Role.CLIENT)

    # --------------------------------------------------------
    # Connect to server
    # --------------------------------------------------------
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDR)

    try:
        # --------------------------------------------------------
        # Send CLIENT_HELLO (round = 0)
        # --------------------------------------------------------
        hello = fsm.encrypt_and_mac(
            opcode=CLIENT_HELLO,
            client_id=CLIENT_ID,
            direction=DIRECTION_C2S,
            plaintext=b"HELLO",
        )
        print(f"--- [Client {CLIENT_ID}] Sending: CLIENT_HELLO | Round: 0 ---")
        send_msg(sock, hello)

        # --------------------------------------------------------
        # Receive SERVER_CHALLENGE
        # --------------------------------------------------------
        reply = recv_msg(sock)
        op_name = OPCODE_NAMES.get(reply['opcode'], 'UNKNOWN')
        print(f"--- [Client {CLIENT_ID}] Recv: {op_name} | Round: {reply['round']} ---")
        fsm.verify_and_decrypt(reply)

        print(f"--- [Client {CLIENT_ID}] Handshake complete | State: {fsm.state.name} ---")

        # --------------------------------------------------------
        # Active Rounds
        # --------------------------------------------------------
        NUM_ROUNDS = 5
        
        for r in range(1, NUM_ROUNDS + 1):
            # Send Data
            val = random.randint(1, 100)
            print(f"--- [Client {CLIENT_ID}] Round {r}: Sending {val} ---")
            
            payload = str(val).encode()
            
            msg = fsm.encrypt_and_mac(
                opcode=CLIENT_DATA,
                client_id=CLIENT_ID,
                direction=DIRECTION_C2S,
                plaintext=payload
            )
            print(f"--- [Client {CLIENT_ID}] Sending: CLIENT_DATA | Round: {msg['round']} | State: {fsm.state.name} ---")
            send_msg(sock, msg)
            
            # Receive Aggregation
            reply = recv_msg(sock)
            op_name = OPCODE_NAMES.get(reply['opcode'], 'UNKNOWN')
            print(f"--- [Client {CLIENT_ID}] Recv: {op_name} | Round: {reply['round']} ---")
            plaintext = fsm.verify_and_decrypt(reply)
            
            if reply["opcode"] != SERVER_AGGR_RESPONSE:
                 raise RuntimeError(f"Unexpected opcode {reply['opcode']}")
            
            # Format: Val || Status(1 byte)
            aggr_val_bytes = plaintext[:-1]
            status = plaintext[-1]
            
            aggr_val = int(aggr_val_bytes.decode())
            print(f"--- [Client {CLIENT_ID}] Round {r}: Aggregation Result = {aggr_val}, Status={status} ---")

    except Exception as e:
        print(f"Client error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()

# server.py

import socket
import struct
import threading
import time

from protocol_fsm import (
    ProtocolFSM,
    Role,
    SERVER_CHALLENGE,
    CLIENT_DATA,
    SERVER_AGGR_RESPONSE,
    TERMINATE,
    OPCODE_NAMES,
)

SERVER_ADDR = ("", 3490)
DIRECTION_S2C = 1
EXPECTED_CLIENTS = 3 # Legacy, not used for limit anymore but maybe for printing?
# We will switch to dynamic.

class ServerState:
    def __init__(self):
        self.lock = threading.Lock()
        self.round_data = {}      # {round: {client_id: value}}
        self.aggr_results = {}    # {round: value}
        self.round_events = {}    # {round: threading.Event}
        self.aggregation_window = 2.0  # Seconds to wait after first submission

    def submit_data(self, rnd, client_id, value):
        with self.lock:
            if rnd not in self.round_data:
                self.round_data[rnd] = {}
                self.round_events[rnd] = threading.Event()
                
                # First submission for this round: Start the timer
                threading.Timer(
                    self.aggregation_window, 
                    self._finalize_aggregation, 
                    args=[rnd]
                ).start()
                print(f"--- [Server] Round {rnd} window started ({self.aggregation_window}s) ---")

            self.round_data[rnd][client_id] = value

    def _finalize_aggregation(self, rnd):
        with self.lock:
            if rnd in self.aggr_results:
                return # Already done

            values = self.round_data.get(rnd, {}).values()
            total = sum(values)
            self.aggr_results[rnd] = total
            
            # Notify waiting threads
            if rnd in self.round_events:
                self.round_events[rnd].set()
            
            print(f"--- [Server] Round {rnd} Aggregation Finalized: Sum={total} (Count={len(values)}) ---")

    def get_result(self, rnd):
        # Block until result is available
        if rnd not in self.round_events:
             # Should be created by submit_data, unless called too early?
             # Safe fallback: wait a bit or check lock
             return None # Should not happen if flow is correct

        self.round_events[rnd].wait() # Blocks here
        
        with self.lock:
            return self.aggr_results.get(rnd)

# Global state
server_state = ServerState()

# ------------------------------------------------------------
# Framing helpers
# ------------------------------------------------------------

def recv_msg(conn) -> dict:
    raw_len = conn.recv(4)
    if len(raw_len) < 4:
        raise RuntimeError("Connection closed")

    length = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
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


def send_msg(conn, msg: dict):
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

    conn.sendall(struct.pack("!I", len(payload)) + payload)


# ------------------------------------------------------------
# Per-client handler
# ------------------------------------------------------------

def handle_client(conn: socket.socket):
    client_id = 0
    try:
        # 1. Handshake (Round 0)
        print(f"--- [Server] Waiting for connection... ---")
        msg = recv_msg(conn)
        client_id = msg["client_id"]
        op_name = OPCODE_NAMES.get(msg['opcode'], 'UNKNOWN')
        print(f"--- [Server] Recv: {op_name} | Client: {client_id} | Round: {msg['round']} ---")

        with open(f"keys/client_{client_id}.key", "rb") as f:
            master_key = f.read()

        fsm = ProtocolFSM(master_key, Role.SERVER)
        plaintext = fsm.verify_and_decrypt(msg)
        
        # Verify HELLO
        if plaintext != b"HELLO":
             raise RuntimeError("Invalid HELLO")

        print(f"--- [Server] State: {fsm.state.name} | Sending SERVER_CHALLENGE ---")
        reply = fsm.encrypt_and_mac(
            opcode=SERVER_CHALLENGE,
            client_id=client_id,
            direction=DIRECTION_S2C,
            plaintext=b"OK",
        )
        send_msg(conn, reply)
        print(f"--- [Server] Sent: SERVER_CHALLENGE | Round: {reply['round']} ---")
        print(f"Client {client_id}: Handshake complete")

        # 2. Aggregation Loop
        # We'll run for a fixed set of rounds for this assignment/verification
        NUM_ROUNDS = 5
        
        for r in range(1, NUM_ROUNDS + 1):
            # Receive CLIENT_DATA
            msg = recv_msg(conn)
            op_name = OPCODE_NAMES.get(msg['opcode'], 'UNKNOWN')
            print(f"--- [Server] Recv: {op_name} | Client: {client_id} | Round: {msg['round']} | State: {fsm.state.name} ---")

            plaintext = fsm.verify_and_decrypt(msg)
            
            if msg["opcode"] != CLIENT_DATA:
                raise RuntimeError(f"Expected CLIENT_DATA, got {msg['opcode']}")

            # Parse integer
            value = int(plaintext.decode())
            print(f"Client {client_id}: Round {r} submitted {value}")

            # Submit to state
            server_state.submit_data(r, client_id, value)
            
            # Wait for result (Dynamic, no barrier)
            aggr_val = server_state.get_result(r)
            
            if aggr_val is None:
                # Fallback if something weird happens
                raise RuntimeError("Failed to get aggregation result")
            
            # Construct Response: Val || Status(0)
            # Status code 0 (success)
            status_code = b"\x00"
            payload = str(aggr_val).encode() + status_code

            print(f"--- [Server] Sending AGGR Result: {aggr_val} | Round: {r} ---")
            reply = fsm.encrypt_and_mac(
                opcode=SERVER_AGGR_RESPONSE,
                client_id=client_id,
                direction=DIRECTION_S2C,
                plaintext=payload,
            )
            send_msg(conn, reply)
            print(f"--- [Server] Sent: SERVER_AGGR_RESPONSE | Round: {reply['round']} ---")
            print(f"Client {client_id}: Round {r} sent result {aggr_val}")

    except Exception as e:
        print(f"Server error (Client {client_id}):", e)
    finally:
        conn.close()


# ------------------------------------------------------------
# Main server loop
# ------------------------------------------------------------

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(SERVER_ADDR)
    sock.listen(EXPECTED_CLIENTS)

    print(f"Server running on port {SERVER_ADDR[1]}, expecting {EXPECTED_CLIENTS} clients")

    try:
        while True:
            conn, _ = sock.accept()
            threading.Thread(
                target=handle_client,
                args=(conn,),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nServer shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
